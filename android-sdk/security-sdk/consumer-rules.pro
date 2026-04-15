# Consumer ProGuard rules for security-sdk AAR consumers.
#
# Keep the public SDK surface and @Keep annotated symbols stable across shrinking.

-keep @androidx.annotation.Keep class * { *; }
-keepclassmembers class * {
  @androidx.annotation.Keep *;
}

# Keep Kotlin metadata (helps reflection / serialization in host apps).
-keep class kotlin.Metadata { *; }

# Public SDK namespace.
-keep class com.bankingsdk.security.** { *; }
