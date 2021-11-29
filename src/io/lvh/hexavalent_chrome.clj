(ns io.lvh.hexavalent-chrome
  (:require
   [babashka.fs :as fs]
   [clojure.java.jdbc :as jdbc]
   [clojure.string :as str])
  (:import
   (org.freedesktop.secret.simple SimpleCollection)
   (javax.crypto SecretKeyFactory Cipher)
   (javax.crypto.spec PBEKeySpec SecretKeySpec IvParameterSpec)
   (java.util Arrays))
  (:gen-class))

(defn ^:private get-root-secret
  []
  (let [coll (SimpleCollection.)
        path (-> coll
                 (.getItems
                  {"application" "chrome"
                   "xdg:schema" "chrome_libsecret_os_crypt_password_v2"})
                 first)]
    (.getSecret coll path)))

(def ^:private default-secret (-> "peanuts" .toCharArray))
(def ^:private the-iv (->> \space byte (repeat 16) byte-array IvParameterSpec.))

(defn ^:private compute-key
  [^chars input]
  (let [salt (-> "saltysalt" (.getBytes "UTF-8"))
        iterations 1
        length (* 16 8) ;; in bits
        spec (PBEKeySpec. input salt iterations length)]
    (-> (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA1")
        (.generateSecret (PBEKeySpec. input salt iterations length))
        (.getEncoded)
        (SecretKeySpec. "AES"))))

(defn decrypt
  [^bytes key ^bytes ctext]
  (let [cipher (doto (Cipher/getInstance "AES/CBC/PKCS5Padding")
                 (.init Cipher/DECRYPT_MODE key the-iv))]
    (.doFinal cipher ctext)))

(defn ^:private get-logins
  []
  (let [base (-> "~/.config/google-chrome" fs/expand-home)]
    (for [db-path (fs/glob base "*/Login Data")
          :let [profile (->> db-path (fs/relativize base) fs/components first)
                db {:dbtype "sqlite" :dbname (str db-path)}]
          login (jdbc/query db ["SELECT * FROM logins;"])]
      (assoc login ::profile profile ::db db))))

(defn succeeds?
  [f]
  (fn [& args]
    (try
      (apply f args) true
      (catch Throwable _ false))))

(def fails?
  (comp complement succeeds?))

(comment
  ((succeeds? #(/ 1 0))) #_false
  ((succeeds? (constantly nil))) #_true
  ((fails? #(/ 1 0))) #_false
  ((fails? (constantly nil))) #_false)

(defn ^:private chop-header
  [^bytes value]
  (Arrays/copyOfRange value 3 (alength value)))

(defn analyze
  []
  (let [key (-> (get-root-secret) (or default-secret) compute-key)
        cant-decrypt? (comp (fails? (partial decrypt key)) chop-header)
        diagnosis
        (fn [login]
          (cond
            (-> login :password_value empty?) :empty-password
            ;;(-> login :username_value empty?) :empty-username
            (-> login :password_value cant-decrypt?) :cant-decrypt
            :else :everything-copacetic))]
    (group-by diagnosis (get-logins))))

(defn fix!
  []
  (let [failures (:cant-decrypt analyze)]
    (when (empty? failures) (println "no failed decryptions!"))
    (doseq [[[profile db] logins] (group-by (juxt ::profile ::db) failures)
            :let [ids (map :id logins)]]
      (println
       (format "Profile %s has bad passwords for %s (ids %s)"
               profile
               (->> logins (map :signon_realm) (str/join ", "))
               (->> ids (str/join ", "))))
      (jdbc/with-db-transaction [t db]
        (doseq [id ids] (jdbc/delete! db :logins ["id = ?" id]))))))
