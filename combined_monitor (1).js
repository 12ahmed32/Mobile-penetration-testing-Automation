Java.perform(function() {
    console.log("[*] Starting Broadcast Intent Monitor...");
    
    // Hook ContextWrapper.sendBroadcast()
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    or 
    ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log("\n=== Broadcast Intent Sent ===");
        console.log("Method: sendBroadcast(Intent)");
        printIntentDetails(intent);
        printStackTrace();
        return this.sendBroadcast(intent);
    };
    
    ContextWrapper.sendBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function(intent, receiverPermission) {
        console.log("\n=== Broadcast Intent Sent ===");
        console.log("Method: sendBroadcast(Intent, String)");
        console.log("Receiver Permission: " + receiverPermission);
        printIntentDetails(intent);
        printStackTrace();
        return this.sendBroadcast(intent, receiverPermission);
    };
    
    // Hook Context.sendBroadcast()
    var Context = Java.use("android.content.Context");
    
    Context.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log("\n=== Broadcast Intent Sent ===");
        console.log("Method: Context.sendBroadcast(Intent)");
        printIntentDetails(intent);
        printStackTrace();
        return this.sendBroadcast(intent);
    };
    
    Context.sendBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function(intent, receiverPermission) {
        console.log("\n=== Broadcast Intent Sent ===");
        console.log("Method: Context.sendBroadcast(Intent, String)");
        console.log("Receiver Permission: " + receiverPermission);
        printIntentDetails(intent);
        printStackTrace();
        return this.sendBroadcast(intent, receiverPermission);
    };
    
    // Hook sendOrderedBroadcast methods
    ContextWrapper.sendOrderedBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function(intent, receiverPermission) {
        console.log("\n=== Ordered Broadcast Intent Sent ===");
        console.log("Method: sendOrderedBroadcast(Intent, String)");
        console.log("Receiver Permission: " + receiverPermission);
        printIntentDetails(intent);
        printStackTrace();
        return this.sendOrderedBroadcast(intent, receiverPermission);
    };
    
    ContextWrapper.sendOrderedBroadcast.overload('android.content.Intent', 'java.lang.String', 'android.content.BroadcastReceiver', 'android.os.Handler', 'int', 'java.lang.String', 'android.os.Bundle').implementation = function(intent, receiverPermission, resultReceiver, scheduler, initialCode, initialData, initialExtras) {
        console.log("\n=== Ordered Broadcast Intent Sent ===");
        console.log("Method: sendOrderedBroadcast with all parameters");
        console.log("Receiver Permission: " + receiverPermission);
        console.log("Initial Code: " + initialCode);
        console.log("Initial Data: " + initialData);
        printIntentDetails(intent);
        printStackTrace();
        return this.sendOrderedBroadcast(intent, receiverPermission, resultReceiver, scheduler, initialCode, initialData, initialExtras);
    };
    
    // Hook sendStickyBroadcast (deprecated but still might be used)
    ContextWrapper.sendStickyBroadcast.overload('android.content.Intent').implementation = function(intent) {
        console.log("\n=== Sticky Broadcast Intent Sent ===");
        console.log("Method: sendStickyBroadcast(Intent)");
        printIntentDetails(intent);
        printStackTrace();
        return this.sendStickyBroadcast(intent);
    };
    
    // Function to print intent details
    function printIntentDetails(intent) {
        try {
            if (intent) {
                var action = intent.getAction();
                var data = intent.getDataString();
                var component = intent.getComponent();
                var categories = intent.getCategories();
                var extras = intent.getExtras();
                var flags = intent.getFlags();
                
                console.log("Action: " + (action ? action : "null"));
                console.log("Data: " + (data ? data : "null"));
                
                if (component) {
                    console.log("Component: " + component.toShortString());
                }
                
                if (categories) {
                    var cats = Java.cast(categories, Java.use("java.util.Set"));
                    var iterator = cats.iterator();
                    var categoryList = [];
                    while (iterator.hasNext()) {
                        categoryList.push(iterator.next());
                    }
                    console.log("Categories: " + categoryList.join(", "));
                }
                
                console.log("Flags: 0x" + flags.toString(16));
                
                if (extras) {
                    console.log("\nExtras:");
                    var bundle = Java.cast(extras, Java.use("android.os.Bundle"));
                    var keySet = bundle.keySet();
                    var iterator = keySet.iterator();
                    
                    while (iterator.hasNext()) {
                        var key = iterator.next();
                        var value = bundle.get(key);
                        var valueStr;
                        
                        try {
                            if (value) {
                                // Try to get string representation
                                if (value.getClass().getName().indexOf("String") !== -1) {
                                    valueStr = value;
                                } else if (value.getClass().getName().indexOf("Integer") !== -1 ||
                                           value.getClass().getName().indexOf("Long") !== -1 ||
                                           value.getClass().getName().indexOf("Boolean") !== -1 ||
                                           value.getClass().getName().indexOf("Double") !== -1 ||
                                           value.getClass().getName().indexOf("Float") !== -1) {
                                    valueStr = value.toString();
                                } else if (value.getClass().getName().indexOf("Bundle") !== -1) {
                                    valueStr = "[Bundle]";
                                } else if (value.getClass().getName().indexOf("ArrayList") !== -1) {
                                    valueStr = "[ArrayList of size " + value.size() + "]";
                                } else {
                                    valueStr = value.toString();
                                }
                            } else {
                                valueStr = "null";
                            }
                        } catch (e) {
                            valueStr = "[Cannot convert: " + e + "]";
                        }
                        
                        console.log("  " + key + " = " + valueStr);
                    }
                }
            }
        } catch (e) {
            console.log("Error parsing intent: " + e);
        }
    }
    
    // Function to print stack trace
    function printStackTrace() {
        console.log("\nStack Trace:");
        var Exception = Java.use("java.lang.Exception");
        var ex = Exception.$new();
        var stackTrace = ex.getStackTrace();
        
        // Filter to show only relevant app stack traces
        for (var i = 0; i < stackTrace.length; i++) {
            var stackLine = stackTrace[i].toString();
            // Show lines that are from the app (not Android framework)
            if (stackLine.indexOf("android.") === -1 && stackLine.indexOf("com.android.") === -1) {
                console.log("  " + stackLine);
            }
        }
        
        // Clean up
        ex.$dispose();
    }
    
    console.log("[*] Broadcast monitoring hooks installed!");
});
function hook(intent) {
    var text = [];
    var tmp = null;

    try {
        tmp = intent.getComponent();
        if (tmp) {
            text.push("Package Name: " + tmp.getPackageName());
            text.push("Class Name: " + tmp.getClassName());
        }

        tmp = intent.getAction();
        if (tmp) text.push("Action: " + tmp);

        tmp = intent.getData();
        if (tmp) text.push("URI: " + tmp.toString());

        tmp = intent.getFlags();
        text.push("Flags: " + tmp);

        tmp = intent.getType();
        if (tmp) text.push("Type: " + tmp);

        tmp = intent.getExtras();
        if (tmp) {
            var keys = tmp.keySet().iterator();
            while (keys.hasNext()) {
                var key = keys.next();
                text.push("Extra: " + key + " = " + tmp.get(key));
            }
        }

    } catch (e) {
        console.log("Intent parse error: " + e);
    }

    console.log("\n[INTENT]\n" + text.join("\n") + "\n--------------------");
}

var Context = Java.use("android.content.Context");

//
//Context.sendBroadcast.overload("android.content.Intent").implementation =
//function (intent) {
//    console.log("\n[BROADCAST SENT]");
//    hook(intent);
//    return this.sendBroadcast(intent);
//};


Java.perform(function () {

    var Activity = Java.use("android.app.Activity");

    Activity.onCreate.overload("android.os.Bundle").implementation = function (bundle) {

        try {
            var intent = this.getIntent();
            if (intent) {
                hook(intent);
            }
        } catch (e) {
            console.log("onCreate hook error: " + e);
        }


        // ✅ Call the ORIGINAL onCreate
        return Activity.onCreate.overload("android.os.Bundle").call(this, bundle);
    };

});