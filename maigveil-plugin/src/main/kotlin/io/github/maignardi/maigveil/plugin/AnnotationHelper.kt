package io.github.maignardi.maigveil.plugin

import org.objectweb.asm.tree.AnnotationNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.MethodNode

object AnnotationHelper {
    const val ANN_OBFUSCATE = "Lio/github/maignardi/maigveil/annotations/VeilObfuscate;"
    const val ANN_VIRTUALIZE = "Lio/github/maignardi/maigveil/annotations/VeilVirtualize;"
    const val ANN_CONTROL_FLOW = "Lio/github/maignardi/maigveil/annotations/VeilControlFlow;"
    const val ANN_STRING = "Lio/github/maignardi/maigveil/annotations/VeilString;"
    const val ANN_ASSET = "Lio/github/maignardi/maigveil/annotations/VeilAsset;"
    const val ANN_IGNORE = "Lio/github/maignardi/maigveil/annotations/VeilIgnore;"
    const val ANN_KOTLIN_METADATA = "Lkotlin/Metadata;"

    private val VEIL_ANNOTATIONS = setOf(
        ANN_OBFUSCATE,
        ANN_VIRTUALIZE,
        ANN_CONTROL_FLOW,
        ANN_STRING,
        ANN_ASSET,
        ANN_IGNORE
    )

    fun hasAnnotation(annotations: List<AnnotationNode>?, desc: String): Boolean =
        annotations?.any { it.desc == desc } == true

    fun findAnnotation(annotations: List<AnnotationNode>?, desc: String): AnnotationNode? =
        annotations?.firstOrNull { it.desc == desc }

    fun getIntArg(ann: AnnotationNode?, name: String, defaultVal: Int): Int {
        val vals = ann?.values ?: return defaultVal
        var i = 0
        while (i + 1 < vals.size) {
            if (vals[i] == name && vals[i + 1] is Int) {
                return vals[i + 1] as Int
            }
            i += 2
        }
        return defaultVal
    }

    fun isIgnored(cn: ClassNode): Boolean =
        hasAnnotation(cn.invisibleAnnotations, ANN_IGNORE) ||
            hasAnnotation(cn.visibleAnnotations, ANN_IGNORE)

    fun isIgnored(mn: MethodNode): Boolean =
        hasAnnotation(mn.invisibleAnnotations, ANN_IGNORE) ||
            hasAnnotation(mn.visibleAnnotations, ANN_IGNORE)

    fun isIgnored(fn: FieldNode): Boolean =
        hasAnnotation(fn.invisibleAnnotations, ANN_IGNORE) ||
            hasAnnotation(fn.visibleAnnotations, ANN_IGNORE)

    fun hasVeilAnnotation(cn: ClassNode): Boolean =
        VEIL_ANNOTATIONS.any {
            hasAnnotation(cn.invisibleAnnotations, it) || hasAnnotation(cn.visibleAnnotations, it)
        }

    fun hasVeilAnnotation(mn: MethodNode): Boolean =
        VEIL_ANNOTATIONS.any {
            hasAnnotation(mn.invisibleAnnotations, it) || hasAnnotation(mn.visibleAnnotations, it)
        }

    fun stripAnnotations(
        cn: ClassNode,
        stripVeil: Boolean,
        stripKotlinMetadata: Boolean,
        isProtectedClass: Boolean
    ) {
        fun filterList(list: MutableList<AnnotationNode>?, stripMeta: Boolean): MutableList<AnnotationNode>? {
            if (list == null) return null
            list.removeAll { ann ->
                (stripVeil && ann.desc in VEIL_ANNOTATIONS) ||
                    (stripMeta && ann.desc == ANN_KOTLIN_METADATA)
            }
            return list
        }

        val stripMeta = stripKotlinMetadata && isProtectedClass
        cn.invisibleAnnotations = filterList(cn.invisibleAnnotations, stripMeta)
        cn.visibleAnnotations = filterList(cn.visibleAnnotations, stripMeta)

        for (mn in cn.methods) {
            mn.invisibleAnnotations = filterList(mn.invisibleAnnotations, false)
            mn.visibleAnnotations = filterList(mn.visibleAnnotations, false)
        }
        for (fn in cn.fields) {
            fn.invisibleAnnotations = filterList(fn.invisibleAnnotations, false)
            fn.visibleAnnotations = filterList(fn.visibleAnnotations, false)
        }
    }
}

class VaultCollector(private val seedData: BuildSeedData) {
    private var nextStringId = 1
    private var nextProgramId = 1

    val strings = mutableListOf<VaultStringEntry>()
    val vmPrograms = mutableListOf<VaultVmProgram>()

    fun registerString(className: String, methodName: String, plaintext: String): Int {
        val id = nextStringId++
        val classHash = MaigVeilCrypto.fnv1a32(className)
        val methodHash = MaigVeilCrypto.fnv1a32(methodName)
        val cipher = MaigVeilCrypto.arxEncrypt(
            sessionKey = seedData.sessionKey,
            schedule = seedData.arxSchedule,
            classHash = classHash,
            methodHash = methodHash,
            stringIndex = id,
            plaintext = plaintext.toByteArray(Charsets.UTF_8)
        )
        strings += VaultStringEntry(
            id = id,
            classHash = classHash,
            methodHash = methodHash,
            strIndex = id,
            cipherBytes = cipher
        )
        return id
    }

    fun allocateProgramId(): Int = nextProgramId++

    fun registerVmProgram(program: VaultVmProgram) {
        vmPrograms += program
    }
}
