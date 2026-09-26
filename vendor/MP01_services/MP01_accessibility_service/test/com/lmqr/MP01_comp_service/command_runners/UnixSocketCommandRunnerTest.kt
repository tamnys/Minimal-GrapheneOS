package com.lmqr.hMP01_comp_service.command_runners

import java.io.IOException
import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UnixSocketCommandRunnerTest {
    @Test
    fun runCommandsConnectsSendsInOrderAndDisconnects() {
        val client = RecordingClient()
        val runner = UnixSocketCommandRunner { client }

        assertTrue(runner.runCommands(arrayOf("first", "second")))

        assertEquals(
            listOf("connect", "send:first", "send:second", "disconnect"),
            client.events
        )
    }

    @Test
    fun separateBatchesUseSeparateClients() {
        val clients = mutableListOf<RecordingClient>()
        val runner = UnixSocketCommandRunner {
            RecordingClient().also(clients::add)
        }

        assertTrue(runner.runCommands(arrayOf("first")))
        assertTrue(runner.runCommands(arrayOf("second")))

        assertEquals(2, clients.size)
        assertEquals(listOf("connect", "send:first", "disconnect"), clients[0].events)
        assertEquals(listOf("connect", "send:second", "disconnect"), clients[1].events)
    }

    @Test
    fun sendFailureStillDisconnects() {
        val client = RecordingClient(replyOnCommand = mapOf("broken" to CommandReply.FAILED))
        val runner = UnixSocketCommandRunner { client }

        assertFalse(runner.runCommands(arrayOf("broken", "later")))
        assertEquals(listOf("connect", "send:broken", "disconnect"), client.events)
    }

    @Test
    fun propertyAcceptanceIsNotReportedAsHardwareSuccess() {
        val client = RecordingClient(replyOnCommand = mapOf("au_br1" to CommandReply.ACCEPTED))
        val runner = UnixSocketCommandRunner { client }

        assertFalse(runner.runCommands(arrayOf("au_br1", "later")))
        assertEquals(listOf("connect", "send:au_br1", "disconnect"), client.events)
    }

    @Test
    fun transportFailureIsNotReplayed() {
        val client = RecordingClient(failOnCommand = "r")
        val runner = UnixSocketCommandRunner { client }

        assertFalse(runner.runCommands(arrayOf("r")))
        assertEquals(listOf("connect", "send:r", "disconnect"), client.events)
    }

    @Test
    fun replyParserRejectsMissingAndMalformedReplies() {
        assertEquals(CommandReply.APPLIED, reply("OK\n"))
        assertEquals(CommandReply.ACCEPTED, reply("ACCEPTED\n"))
        assertEquals(CommandReply.FAILED, reply("ERR\n"))
        for (invalid in listOf("", "OK", "YES\n", "OK\r\n", "0123456789abcdefg\n")) {
            try {
                reply(invalid)
                throw AssertionError("Accepted invalid reply: $invalid")
            } catch (_: IOException) {
                // Missing, malformed and overlong replies must fail closed.
            }
        }
    }

    private fun reply(value: String) = readCommandReply(ByteArrayInputStream(value.toByteArray()))

    private class RecordingClient(
        private val failOnCommand: String? = null,
        private val replyOnCommand: Map<String, CommandReply> = emptyMap()
    ) : SocketCommandClient {
        val events = mutableListOf<String>()

        override fun connect() {
            events += "connect"
        }

        override fun sendCommand(command: String): CommandReply {
            events += "send:$command"
            if (command == failOnCommand)
                throw IOException("send failed")
            return replyOnCommand[command] ?: CommandReply.APPLIED
        }

        override fun disconnect() {
            events += "disconnect"
        }
    }
}
