Example code to parse Apple receipts without Apple server. Uses Bouncy Castle for crypto stuff.

```
$ mvn clean package
$ java -cp target/apple-0.0.1-SNAPSHOT-jar-with-dependencies.jar com.tensquaregames.examples.apple.Test $(cat fishingclash.receipt) com.tensquaregames.letsfish2
receipt_type: Production, app_item_id: 1151811380, bundle_id: com.tensquaregames.letsfish2, in_app: [quantity: 1, product_id: com.tensquaregames.letsfish2.goldpack_2.T5, transaction_id: 320000424631056, purchase_date: 2018-07-17T12:51:54Z[UTC]]
```
