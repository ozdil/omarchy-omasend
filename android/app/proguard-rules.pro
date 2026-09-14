# OmaSend Models & Serialization
-keep class io.omarchy.omasend.model.** { *; }
-keepclassmembers class io.omarchy.omasend.model.** {
    *** Companion;
    *** serializer(...);
}

# Kotlinx Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.SerializationKt
-keepclassmembers class * {
    @kotlinx.serialization.Serializable <fields>;
}
-keepclassmembers class * {
    *** Companion;
}
-keepclassmembers class * {
    *** serializer(...);
}

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# ZXing
-dontwarn com.google.zxing.**
-keep class com.google.zxing.** { *; }
