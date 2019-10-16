package com.tensquaregames.examples.apple;

import java.time.ZonedDateTime;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;

public class InApp {

    private Integer quantity;
    private String productId;
    private String transactionId;
    private ZonedDateTime purchaseDate;
    private String originalTransactionId;
    private ZonedDateTime originalPurchaseDate;

    static InApp parse(final byte[] data) throws ReceiptParseException {
        try {
            InApp result = new InApp();

            ASN1Set set = ASN1Set.getInstance(data);
            for(ASN1Encodable el: set) {
                ASN1Sequence seq = ASN1Sequence.getInstance(el);
                int type = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
                ASN1OctetString value = ASN1OctetString.getInstance(seq.getObjectAt(2));

                switch(type) {
                case 1701:
                    result.quantity = ASN1Integer.getInstance(value.getOctets()).getValue().intValue();
                    break;
                case 1702:
                    result.productId = DERUTF8String.getInstance(value.getOctets()).getString();
                    break;
                case 1703:
                    result.transactionId = DERUTF8String.getInstance(value.getOctets()).getString();
                    break;
                case 1704:
                    result.purchaseDate = ZonedDateTime.parse(DERIA5String.getInstance(value.getOctets()).getString(), Receipt.RFC3339);
                    break;
                case 1705:
                    result.originalTransactionId = DERUTF8String.getInstance(value.getOctets()).getString();
                    break;
                case 1706:
                    result.originalPurchaseDate = ZonedDateTime.parse(DERIA5String.getInstance(value.getOctets()).getString(), Receipt.RFC3339);
                    break;
                default:
                    break;
                }
            }

            return result;
        } catch(IllegalArgumentException e) {
            throw new ReceiptParseException("unable to parse inApp", e);
        }
    }

    public Integer getQuantity() {
        return quantity;
    }

    public String getProductId() {
        return productId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public ZonedDateTime getPurchaseDate() {
        return purchaseDate;
    }

    public String getOriginalTransactionId() {
        return originalTransactionId;
    }

    public ZonedDateTime getOriginalPurchaseDate() {
        return originalPurchaseDate;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("quantity: " + quantity);
        sb.append(", product_id: " + productId);
        sb.append(", transaction_id: " + transactionId);
        sb.append(", purchase_date: " + purchaseDate);
        return sb.toString();
    }
}
