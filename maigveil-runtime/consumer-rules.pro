# Preserve MaigVeil JNI entry points and bootstrap classes under R8 Full Mode
-keep class io.github.maignardi.maigveil.runtime.MaigVeil { *; }
-keep class io.github.maignardi.maigveil.runtime.MaigVeilNative { *; }
-keep class io.github.maignardi.maigveil.runtime.MaigVeilInitProvider { *; }
-keep class io.github.maignardi.maigveil.runtime.MaigVeilVM { *; }
-keep class io.github.maignardi.maigveil.runtime.MaigVeilAssets { *; }
-keep class io.github.maignardi.maigveil.runtime.MaigVeilBootstrap { *; }
-keep class io.github.maignardi.maigveil.runtime.MaigVeilStatus { *; }
