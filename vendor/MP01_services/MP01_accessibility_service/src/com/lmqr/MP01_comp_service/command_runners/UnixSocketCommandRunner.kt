package com.lmqr.hMP01_comp_service.command_runners

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

internal enum class CommandReply { APPLIED, ACCEPTED, FAILED }

internal fun readCommandReply(stream: InputStream): CommandReply {
    val response = StringBuilder()
    repeat(16) {
        val value = stream.read()
        if (value < 0) throw IOException("E-ink socket closed before reply")
        if (value == '\n'.code) {
            return when (response.toString()) {
                "OK" -> CommandReply.APPLIED
                "ACCEPTED" -> CommandReply.ACCEPTED
                "ERR" -> CommandReply.FAILED
                else -> throw IOException("Invalid E-ink daemon reply")
            }
        }
        if (value !in 32..126) throw IOException("Invalid E-ink daemon reply")
        response.append(value.toChar())
    }
    throw IOException("E-ink daemon reply too long")
}

internal interface SocketCommandClient {
    fun connect()
    fun sendCommand(command: String): CommandReply
    fun disconnect()
}

internal class UnixDomainSocketClient(private val socketName: String) : SocketCommandClient {
    private var socket: LocalSocket? = null
    private var outputStream: OutputStream? = null
    private var inputStream: InputStream? = null

    override fun connect() {
        disconnect()
        val newSocket = LocalSocket()
        try {
            newSocket.connect(LocalSocketAddress(socketName, LocalSocketAddress.Namespace.RESERVED))
            newSocket.soTimeout = REPLY_TIMEOUT_MS
            outputStream = newSocket.outputStream
            inputStream = newSocket.inputStream
            socket = newSocket
        } catch (e: IOException) {
            try {
                newSocket.close()
            } catch (closeError: IOException) {
                e.addSuppressed(closeError)
            }
            throw e
        }
    }

    override fun sendCommand(command: String): CommandReply {
        val stream = outputStream ?: throw IOException("E-ink socket is not connected")
        stream.write((command + "\n").toByteArray(StandardCharsets.UTF_8))
        stream.flush()
        // Never replay after a lost reply: the first command may have executed.
        return readCommandReply(inputStream ?: throw IOException("E-ink socket is not connected"))
    }

    override fun disconnect() {
        val streamToClose = outputStream
        val inputToClose = inputStream
        val socketToClose = socket
        outputStream = null
        inputStream = null
        socket = null

        try {
            streamToClose?.close()
        } catch (e: IOException) {
            e.printStackTrace()
        }

        try {
            inputToClose?.close()
        } catch (e: IOException) {
            e.printStackTrace()
        }

        try {
            socketToClose?.close()
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    private companion object {
        const val REPLY_TIMEOUT_MS = 5000
    }
}

class UnixSocketCommandRunner internal constructor(
    private val clientFactory: () -> SocketCommandClient
) : CommandRunner {
    constructor() : this({ UnixDomainSocketClient("MP01_eink_socket") })

    override fun runCommands(cmds: Array<String>): Boolean {
        if (cmds.isEmpty())
            return true

        val client = clientFactory()
        return try {
            client.connect()
            for (cmd in cmds) {
                when (client.sendCommand(cmd)) {
                    CommandReply.APPLIED -> Unit
                    CommandReply.ACCEPTED, CommandReply.FAILED -> return false
                }
            }
            true
        } catch (_: IOException) {
            false
        } finally {
            client.disconnect()
        }
    }

    override fun onDestroy() = Unit
}
