package com.lmqr.hMP01_comp_service.command_runners

interface CommandRunner {
    fun runCommands(cmds: Array<String>): Boolean
    fun onDestroy()
}
