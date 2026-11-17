package io.github.maignardi.maigveil.runtime

/**
 * Dispatcher for methods virtualized into MaigVeil's C++20 polymorphic bytecode VM.
 * Calls to these methods are synthesized by `VirtualizationPass` in place of the original JVM body.
 */
object MaigVeilVM {

    @JvmStatic
    fun executeInt(programId: Int, args: Array<Any?>?): Int {
        return MaigVeilNative.nativeExecVmInt(programId, args)
    }

    @JvmStatic
    fun executeLong(programId: Int, args: Array<Any?>?): Long {
        return MaigVeilNative.nativeExecVmLong(programId, args)
    }

    @JvmStatic
    fun executeObject(programId: Int, args: Array<Any?>?): Any? {
        return MaigVeilNative.nativeExecVmObj(programId, args)
    }

    @JvmStatic
    fun executeVoid(programId: Int, args: Array<Any?>?) {
        MaigVeilNative.nativeExecVmVoid(programId, args)
    }
}
