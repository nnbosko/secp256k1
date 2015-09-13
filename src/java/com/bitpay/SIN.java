package com.bitpay;

import javax.annotation.Nonnull;

/**
 * A POJO for encapsulating System Identification Numbers (SINs) and other meta data used by BitAuth.
 *
 * Created by mpwd on 9/13/15.
 */
public class SIN {
    public @Nonnull final Long created;
    public @Nonnull final String priv, pub, sin;

    public SIN(@Nonnull final String priv,
               @Nonnull final String pub,
               @Nonnull final String sin,
               @Nonnull final Long created) {
        this.priv = priv;
        this.pub = pub;
        this.sin = sin;
        this.created = created;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final SIN sin1 = (SIN) o;

        if (!created.equals(sin1.created)) return false;
        if (!priv.equals(sin1.priv)) return false;
        if (!pub.equals(sin1.pub)) return false;
        return sin.equals(sin1.sin);

    }

    @Override
    public int hashCode() {
        int result = created.hashCode();
        result = 31 * result + priv.hashCode();
        result = 31 * result + pub.hashCode();
        result = 31 * result + sin.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "SIN{" +
                "created=" + created +
                ", priv='" + priv + '\'' +
                ", pub='" + pub + '\'' +
                ", sin='" + sin + '\'' +
                '}';
    }
}
