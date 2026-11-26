// Fixture for tests/test_binder_api_parse.c: the shape AIDL generates. The
// Stub's static final constants land in the DEX class_def's static_values,
// in field order; the decoys before the TRANSACTION_ fields exercise the
// encoded-value skipping (string, long, boolean, negative, multi-byte int).
package com.anubee.aidl;

public interface IFoo {
    void ping();

    abstract class Stub implements IFoo {
        static final String DESCRIPTOR = "com.anubee.aidl.IFoo";
        static final long SOME_LONG = 0x123456789L;
        static final boolean FLAG = true;
        static final int NEGATIVE = -1;
        static final int TRANSACTION_ping = 1;
        static final int TRANSACTION_sendData = 2;
        static final int TRANSACTION_big = 16777215;
    }
}

// Not a $Stub: its TRANSACTION_ constant must be ignored.
class NotAStub {
    static final int TRANSACTION_decoy = 1;
}

// Hand-written (non-AIDL) Binder interface, like android.content.IContentProvider:
// codes are <NAME>_TRANSACTION constants on the interface itself.
interface IHand {
    // Wire descriptor differs from the class name (as android.database.IBulkCursor
    // declares "android.content.IBulkCursor"): the token matches this, not the class.
    String descriptor = "com.anubee.legacy.IHand";
    int QUERY_TRANSACTION = 1;
    int GET_TYPE_TRANSACTION = 2;
    String NOT_A_CODE_TRANSACTION = "x";
    int UNRELATED = 3;
}
