(ns secp256k1.math
  (:refer-clojure :exclude [even?])
  (:require [sjcl]
            [secp256k1.formatting :refer [add-leading-zero-if-necessary]]
            [goog.array :refer [toArray]]))

(defn even?
  "Patch the usual cljs.core/even? to work for sjcl.bn instances"
  [n]
  (if (instance? js/sjcl.bn n)
    (.equals (.mod n 2) 0)
    (cljs.core/even? n)))

(defn modular-square-root
  "Compute the square root of a number modulo a prime"
  [n modulus]
  (let [modulus (new js/sjcl.bn modulus)
        n       (.mod (new js/sjcl.bn n) modulus)
        mod8    (-> modulus (.mod 8) .toString js/parseInt)]
    (assert (.greaterEquals n 2),
            "Argument must be greater than or equal to 2")
    (assert (.greaterEquals modulus 0),
            "Modulus must be non-negative")
    (cond
      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_equal_to_2
      (.equals modulus 2)
      (.mod n modulus)

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_3_modulo_4
      (or (= mod8 3) (= mod8 7))
      (let [m (-> modulus (.add 1) .normalize .halveM .halveM)]
        (.powermod n m modulus))

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_5_modulo_8
      (= mod8 5)
      (let [m (-> modulus (.sub 5) .normalize .halveM .halveM .halveM)
            v (.powermod (.add n n) m modulus)
            i (-> (.mul v v) (.mul n) (.mul 2) (.sub 1) (.mod modulus))]
        (-> n (.mul v) (.mul i) (.mod modulus)))

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_1_modulo_8
      (= mod8 1)
      (let [q   (-> modulus (.sub 1) .normalize)
            e   (->> q
                     (iterate #(.halveM %))
                     (take-while even?)
                     count)
            two (new js/sjcl.bn 2)
            z   (->> (range) rest rest
                     (map #(new js/sjcl.bn %))
                     (map #(.powermod % q modulus))
                     (filter
                      #(not
                        (.equals
                         (.powermod % (.power two (- e 1)) modulus)
                         1)))
                     first)
            x   (.powermod n (-> q (.sub 1) .normalize .halveM) modulus)]
        (loop [y z,
               r e,
               v (-> n (.mul x) (.mod modulus)),
               w (-> n (.mul x) (.mul x) (.mod modulus))]
          (if (.equals w 1)
            v
            (let [k (->> (range)
                         (map #(vector
                                %
                                (.powermod w (.power two %) modulus)))
                         (filter #(.equals (second %) 1))
                         first first)
                  d (.powermod y (.power two (- r k 1)) modulus)
                  y (.mod (.mul d d) modulus)
                  v (.mod (.mul d v) modulus)
                  w (.mod (.mul w y) modulus)]
              (recur y k v w)))))

      :else
      (throw (ex-info "Cannot compute a square root for a non-prime modulus"
                      {:argument n,
                       :modulus modulus})))))

(js* "
function isaac() {
    var m = Array(256),  // internal memory
        acc = 0,  // accumulator
        brs = 0,  // last result
        cnt = 0,  // counter
        r = Array(256),  // result array
        gnt = 0,  // generation counter
        this_isaac = this;


    /* private: 32-bit integer safe adder */
    function add(x, y) {
        var lsb = (x & 0xffff) + (y & 0xffff);

        var msb = (x >>> 16) + (y >>> 16) + (lsb >>> 16);

        return (msb << 16) | (lsb & 0xffff);
    }


    /* public: initialisation */
    function reset() {
        acc = brs = cnt = 0;

        for (var i = 0; i < 256; ++ i) m[i] = r[i] = 0;
        gnt = 0;

        return this_isaac;
    }


    /* public: seeding function */
    function seed(s) {
        var a, b, c, d, e, f, g, h, i;


        /* seeding the seeds of love */
        a = b = c = d = e = f = g = h = 0x9e3779b9;

        if (s && typeof (s) === \"number\") {
            s = [
                s
            ];
        }

        if (s instanceof Array) {
            reset();

            for (i = 0; i < s.length; i ++) r[i & 0xff] += (typeof (s[i]) === \"number\") ? s[i] : 0;
        }


        /* private: seed mixer */
        function seed_mix() {
            a ^= b << 11;
            d = add(d, a);
            b = add(b, c);
            b ^= c >>> 2;
            e = add(e, b);
            c = add(c, d);
            c ^= d << 8;
            f = add(f, c);
            d = add(d, e);
            d ^= e >>> 16;
            g = add(g, d);
            e = add(e, f);
            e ^= f << 10;
            h = add(h, e);
            f = add(f, g);
            f ^= g >>> 4;
            a = add(a, f);
            g = add(g, h);
            g ^= h << 8;
            b = add(b, g);
            h = add(h, a);
            h ^= a >>> 9;
            c = add(c, h);
            a = add(a, b);
        }

        for (i = 0; i < 4; i ++)


        /* scramble it */
        seed_mix();

        for (i = 0; i < 256; i += 8) {
            if (s) {
                /* use all the information in the seed */
                a = add(a, r[i + 0]);
                b = add(b, r[i + 1]);
                c = add(c, r[i + 2]);
                d = add(d, r[i + 3]);
                e = add(e, r[i + 4]);
                f = add(f, r[i + 5]);
                g = add(g, r[i + 6]);
                h = add(h, r[i + 7]);
            }

            seed_mix();


            /* fill in m[] with messy stuff */
            m[i + 0] = a;
            m[i + 1] = b;
            m[i + 2] = c;
            m[i + 3] = d;
            m[i + 4] = e;
            m[i + 5] = f;
            m[i + 6] = g;
            m[i + 7] = h;
        }

        if (s) {
            /* do a second pass to make all of the seed affect all of m[] */
            for (i = 0; i < 256; i += 8) {
                a = add(a, m[i + 0]);
                b = add(b, m[i + 1]);
                c = add(c, m[i + 2]);
                d = add(d, m[i + 3]);
                e = add(e, m[i + 4]);
                f = add(f, m[i + 5]);
                g = add(g, m[i + 6]);
                h = add(h, m[i + 7]);
                seed_mix();


                /* fill in m[] with messy stuff (again) */
                m[i + 0] = a;
                m[i + 1] = b;
                m[i + 2] = c;
                m[i + 3] = d;
                m[i + 4] = e;
                m[i + 5] = f;
                m[i + 6] = g;
                m[i + 7] = h;
            }
        }

        prng();


        /* fill in the first set of results */
        gnt = 256;


        /* prepare to use the first set of results */
        return this_isaac;
    }

    seed((Math.random() * 0xffffffff) ^ Time.now());


    /* public: isaac generator, n = number of run */
    function prng(n) {
        var i, x, y;

        n = (n && typeof (n) === \"number\") ? Math.abs(Math.floor(n)) : 1;

        while (n --) {
            cnt = add(cnt, 1);
            brs = add(brs, cnt);

            for (i = 0; i < 256; i ++) {
                switch (i & 3) {
                    case 0:
                        acc ^= acc << 13;
                        break;

                    case 1:
                        acc ^= acc >>> 6;
                        break;

                    case 2:
                        acc ^= acc << 2;
                        break;

                    case 3:
                        acc ^= acc >>> 16;
                        break;
                }

                acc = add(m[(i + 128) & 0xff], acc);
                x = m[i];
                m[i] = y = add(m[(x >>> 2) & 0xff], add(acc, brs));
                r[i] = brs = add(m[(y >>> 10) & 0xff], x);
            }
        }

        return this_isaac;
    }


    /* public: return a random number between */
    function rand() {
        if (0 !== gnt --) {
            prng();
            gnt = 255;
        }

        return r[gnt];
    }


    /* public: return internals in an object*/
    function internals() {
        return {
            a: acc,
            b: brs,
            c: cnt,
            m: m,
            r: r
        };
    }

    this_isaac.reset = reset;
    this_isaac.seed = seed;
    this_isaac.prng = prng;
    this_isaac.rand = rand;
    this_isaac.internals = internals;
}
")

(defn- secure-random-bytes
  "Generate secure random bytes in a platform independent manner"
  ;; http://stackoverflow.com/a/19203948/586893
  [byte-count]
  (assert (integer? byte-count), "Argument must be an integer")
  (assert (< 0 byte-count), "Argument must greater than 0")
  (cond
    (and (exists? js/window)
         (exists? js/window.crypto)
         (exists? js/window.crypto.getRandomValues)
         (exists? js/Uint8Array))
    (->> (doto (new js/Uint8Array byte-count)
           js/window.crypto.getRandomValues)
         toArray)

    ;; IE
    (and (exists? js/window)
         (exists? js/window.msCrypto)
         (exists? js/window.msCrypto.getRandomValues)
         (exists? js/Uint8Array))
    (->> (doto (new js/Uint8Array byte-count)
           js/window.msCrypto.getRandomValues)
         toArray)

    ;; TODO: fallback to isaac.js or fix SJCL somehow
    ;; https://github.com/rubycon/isaac.js/blob/master/isaac.js

    :else
    (throw (ex-info "Could not securely generate random words"
                    {:byte-count byte-count}))))

(defn secure-random
  "Generate a secure random sjcl.bn, takes a maximal value as an argument"
  [arg]
  (let [n          (new js/sjcl.bn arg)
        byte-count (-> n .bitLength (/ 8))
        bytes      (secure-random-bytes byte-count)]
    (-> bytes
        (->> (map #(add-leading-zero-if-necessary
                    (.toString % 16)))
             (apply str)
             (new js/sjcl.bn))
        (.mod n))))
