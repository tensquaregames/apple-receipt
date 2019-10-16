package com.tensquaregames.examples.apple;

public class ReceiptParseException extends Exception {

    private static final long serialVersionUID = 8234548127868220263L;

    public ReceiptParseException(String message) {
        super(message);
    }

    public ReceiptParseException(String message, Throwable cause) {
        super(message, cause);
    }

}
