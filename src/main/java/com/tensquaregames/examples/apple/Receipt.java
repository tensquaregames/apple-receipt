package com.tensquaregames.examples.apple;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;

/**
 * Class representing a single Apple receipt. Do remember that multiple IAPs may be present in single receipt.
 * No verification of fields is made so each one might be null if not present in receipt.
 */
public class Receipt implements Iterable<InApp> {

    static final DateTimeFormatter RFC3339 = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneId.of("UTC"));
    static final X509Certificate APPLE_CA_CERT;

    static {
        try {
            try(InputStream in = Receipt.class.getResourceAsStream("/apple.crt")) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                APPLE_CA_CERT = (X509Certificate) factory.generateCertificate(in);
            }
        } catch(IOException | CertificateException e) {
            throw new RuntimeException("unable to load apple.crt", e);
        }
    }

    private String receiptType;
    private Integer appItemId;
    private String bundleId;
    private String applicationVersion;
    private ZonedDateTime receiptCreationDate;
    private Integer downloadId;
    private Integer versionExternalIdentifier;
    private ZonedDateTime originalPurchaseDate;
    private String originalApplicationVersion;
    private Collection<InApp> inApps = new LinkedList<>();

    /**
     * Parses Apple receipt as described in https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ValidateLocally.html
     *
     * @param data apple receipt blob.
     * @param expectedBundleId bundle ID of application which receipt is being parsed.
     * @throws ReceiptParseException if receipt cannot be parsed, Apple signature is invalid or bundle ID is from different app.
     */
    public static Receipt parse(final byte[] data, final String expectedBundleId) throws ReceiptParseException {
        try {
            Receipt result = new Receipt();

            CMSSignedData cms = new CMSSignedData(data);
            if(!validateSignature(cms)) {
                throw new ReceiptParseException("unable to validate signature");
            }

            ASN1Set set = ASN1Set.getInstance(cms.getSignedContent().getContent());
            for(ASN1Encodable el: set) {
                ASN1Sequence seq = ASN1Sequence.getInstance(el);
                int type = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
                ASN1OctetString value = ASN1OctetString.getInstance(seq.getObjectAt(2));

                // https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html
                switch(type) {
                case 0:
                    result.receiptType = DERUTF8String.getInstance(value.getOctets()).getString();
                    break;
                case 1:
                    result.appItemId = ASN1Integer.getInstance(value.getOctets()).getValue().intValue();
                    break;
                case 2:
                    result.bundleId = DERUTF8String.getInstance(value.getOctets()).getString();
                    break;
                case 3:
                    result.applicationVersion = DERUTF8String.getInstance(value.getOctets()).getString();
                    break;
                case 12:
                    result.receiptCreationDate = ZonedDateTime.parse(DERIA5String.getInstance(value.getOctets()).getString(), RFC3339);
                    break;
                case 15:
                    result.downloadId = ASN1Integer.getInstance(value.getOctets()).getValue().intValue();
                    break;
                case 16:
                    result.versionExternalIdentifier = ASN1Integer.getInstance(value.getOctets()).getValue().intValue();
                    break;
                case 17:
                    result.inApps.add(InApp.parse(value.getOctets()));
                    break;
                case 18:
                    result.originalPurchaseDate = ZonedDateTime.parse(DERIA5String.getInstance(value.getOctets()).getString(), RFC3339);
                    break;
                case 19:
                    result.originalApplicationVersion = DERUTF8String.getInstance(value.getOctets()).getString();
                    break;
                default:
                    break;
                }
            }

            if(!expectedBundleId.equals(result.bundleId)) {
                throw new ReceiptParseException("invalid bundle_id: " + result.bundleId);
            }

            return result;
        } catch(CMSException | IllegalArgumentException e) {
            throw new ReceiptParseException("unable to parse receipt", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static boolean validateSignature(final CMSSignedData data) throws ReceiptParseException {
        // certificates included in PKCS#7 message
        Store<X509CertificateHolder> certStore = data.getCertificates();

        // more or less available signatures, there can be multiple ones
        for(SignerInformation signer: data.getSignerInfos()) {
            // try to find certificate that signs given signature
            for(Object o: certStore.getMatches(signer.getSID())) {
                X509CertificateHolder cert = (X509CertificateHolder)o;
                try {
                    if(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {
                        // if the signature is valid, then verify that the certificate that signs it is signed by Apple
                        if(validateCertificate(certStore, cert)) {
                            return true;
                        }
                        // otherwise continue searching
                    }
                } catch (OperatorCreationException | CertificateException | CMSException e) {
                    throw new ReceiptParseException("unable to check signature", e);
                }
            }
        }

        return false;
    }

    /**
     * Simplified verification that given certificate is signed by Apple CA. Simplified, because it assumes that there is exactly one intermediate certificate
     * between certificate being checked and root. In theory PKCS#7 permits multiple ones, be let's assume Apple sticks to standard of one itermediate.
     */
    @SuppressWarnings({ "unchecked", "unused" })
    private static boolean validateCertificate(final Store<X509CertificateHolder> store, final X509CertificateHolder cert) throws ReceiptParseException {
        // search for the intermediate
        AttributeCertificateIssuer selector = new AttributeCertificateIssuer(cert.getIssuer());
        Collection<X509CertificateHolder> matches = store.<X509CertificateHolder>getMatches(selector);
        if(matches.isEmpty()) {
            return false;
        }

        // yeah, there can also be multiple intermediates
        for(X509CertificateHolder intermediate: matches) {
            try {
                // if intermediate signs the checked cert and root CA signs the intermediate then we are ok
                if(cert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(intermediate)) && intermediate.isSignatureValid(new JcaContentVerifierProviderBuilder().build(APPLE_CA_CERT))) {
                    return true;
                }
                // otherwise continue searching
            } catch (OperatorCreationException | CertException | CertificateException e) {
                throw new ReceiptParseException("unable to check certificate", e);
            }
        }

        return false;
    }

    public String getReceiptType() {
        return receiptType;
    }

    public Integer getAppItemId() {
        return appItemId;
    }

    public String getBundleId() {
        return bundleId;
    }

    public String getApplicationVersion() {
        return applicationVersion;
    }

    public ZonedDateTime getReceiptCreationDate() {
        return receiptCreationDate;
    }

    public Integer getDownloadId() {
        return downloadId;
    }

    public Integer getVersionExternalIdentifier() {
        return versionExternalIdentifier;
    }

    public ZonedDateTime getOriginalPurchaseDate() {
        return originalPurchaseDate;
    }

    public String getOriginalApplicationVersion() {
        return originalApplicationVersion;
    }

    @Override
    public Iterator<InApp> iterator() {
        return inApps.iterator();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("receipt_type: " + receiptType);
        sb.append(", app_item_id: " + appItemId);
        sb.append(", bundle_id: " + bundleId);
        sb.append(", in_app: [");
        for(InApp inApp: inApps) {
            sb.append(inApp.toString());
        }
        sb.append("]");
        return sb.toString();
    }

}
