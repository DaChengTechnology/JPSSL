# jpssl JNI 使用 RegisterNatives，native 方法按 (类名,方法名,签名) 注册；
# 若开启 minify，需保留 native 方法名与 RsaKey 类。
-keepclasseswithmembernames class * {
    native <methods>;
}
-keep class io.github.jpssl.Jpssl { *; }
-keepclassmembers class io.github.jpssl.Jpssl$RsaKey { <init>([B[B[B)V; }
