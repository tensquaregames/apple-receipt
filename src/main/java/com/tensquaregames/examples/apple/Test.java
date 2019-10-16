package com.tensquaregames.examples.apple;

import java.util.Base64;

public class Test {

    public static void main(String[] args) throws ReceiptParseException {

        if(args.length != 2) {
            System.err.println("usage: base64_encoded_receipt expected_bundle_id");
            return;
        }

        byte[] data = Base64.getDecoder().decode(args[0]);

        Receipt receipt = Receipt.parse(data, args[1]);

        System.out.println(receipt);
    }

}
