package io.github.maignardi.maigveil.annotations

/**
 * Protection intensity levels configurable per class or method.
 */
enum class VeilProfileLevel {
    /** Inherit the global profile configured in the `maigVeil` Gradle DSL. */
    INHERIT,
    /** Lightweight string encryption and basic metadata stripping. */
    LIGHT,
    /** Balanced control flow flattening, string encryption, and call indirection. */
    BALANCED,
    /** Maximum obfuscation: full flattening, heavy opaque predicates, and zero-trace secrets. */
    PARANOID
}

/**
 * Marks a class or function for comprehensive MaigVeil bytecode protection
 * (polymorphic string encryption, control flow flattening, and call indirection).
 *
 * Retained at [AnnotationRetention.BINARY] for build-time ASM processing and
 * stripped from the final bytecode when `antiTamper.stripAnnotations` is enabled.
 */
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.CONSTRUCTOR
)
annotation class VeilObfuscate(
    val profile: VeilProfileLevel = VeilProfileLevel.INHERIT
)

/**
 * Marks a method to be compiled into MaigVeil's custom polymorphic bytecode
 * and executed inside the native C++20 `libmaigveil.so` virtual machine.
 *
 * The original JVM method body is completely removed and replaced with a JNI bridge
 * invocation to `MaigVeilVM.execute*`.
 */
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.FUNCTION)
annotation class VeilVirtualize

/**
 * Marks a class or method for Control Flow Flattening and mathematical
 * Opaque Predicate injection.
 *
 * @property flatteningProbability Percentage (0..100) of basic blocks flattened; `-1` uses DSL default.
 * @property opaquePredicatesLevel Opaque predicate complexity (0..2); `-1` uses DSL default.
 */
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.CONSTRUCTOR
)
annotation class VeilControlFlow(
    val flatteningProbability: Int = -1,
    val opaquePredicatesLevel: Int = -1
)

/**
 * Marks a class, function, or property/field for polymorphic ARX string and constant encryption.
 *
 * @property zeroTrace If true, favors zero-trace native buffer handling where applicable.
 */
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.FIELD,
    AnnotationTarget.PROPERTY
)
annotation class VeilString(
    val zeroTrace: Boolean = true
)

/**
 * Declares an asset-backed secret reference that is encrypted at build time
 * using ChaCha20-Poly1305 and decrypted on demand by `MaigVeilAssets`.
 */
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.FIELD
)
annotation class VeilAsset(
    val assetPath: String
)

/**
 * Excludes the annotated class, function, or field from all MaigVeil bytecode transformations.
 */
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.CONSTRUCTOR,
    AnnotationTarget.FIELD,
    AnnotationTarget.PROPERTY
)
annotation class VeilIgnore
