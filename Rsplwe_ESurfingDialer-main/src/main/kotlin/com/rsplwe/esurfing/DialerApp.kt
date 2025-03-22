package com.rsplwe.esurfing

import com.rsplwe.esurfing.States.isRunning
import com.rsplwe.esurfing.hook.Session
import org.apache.commons.cli.*
import org.apache.commons.cli.Options
import org.apache.log4j.Logger
import kotlin.system.exitProcess
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object DialerApp {

    private val logger: Logger = Logger.getLogger(DialerApp::class.java)

    @JvmStatic
    fun main(args: Array<String>) {
        // root directory
        if (!States.rootDir.exists()) States.rootDir.mkdirs()
        if (States.rootDir.isFile) throw IllegalArgumentException("rootDir must be directory: " + States.rootDir)

        val options = Options()
        val loginUser = Option.builder("u").longOpt("user")
            .argName("user")
            .hasArg()
            .required(true)
            .desc("Login User (Phone Number or Other)").build()
        val loginPassword = Option.builder("p").longOpt("password")
            .argName("password")
            .hasArg()
            .required(true)
            .desc("Login User Password").build()
        val userIp = Option.builder("t").longOpt("userIp")
            .argName("userIp")
            .hasArg()
            .required(true)
            .desc("Login Target Ip").build()
        val acIp = Option.builder("a").longOpt("acIp")
            .argName("acIp")
            .hasArg()
            .required(true)
            .desc("Authorization Server IP").build()
        val smsCode = Option.builder("s").longOpt("sms")
            .argName("sms")
            .hasArg()
            .required(false)
            .desc("Pre-enter verification code").build()
        options.addOption(loginUser)
        options.addOption(loginPassword)
        options.addOption(userIp)
        options.addOption(acIp)
        options.addOption(smsCode)

        val cmd: CommandLine
        val parser: CommandLineParser = DefaultParser()
        val helper = HelpFormatter()

        try {
            cmd = parser.parse(options, args)
        } catch (e: ParseException) {
            logger.error(e.message)
            helper.printHelp("ESurfingDialer", options)
            exitProcess(1)
        }

        val client = Client(
            Options(
                cmd.getOptionValue("user"),
                cmd.getOptionValue("password"),
                cmd.getOptionValue("userIp"),
                cmd.getOptionValue("acIp"),
                cmd.getOptionValue("sms") ?: "",
            )
        )

        // 启动后台线程，每 5 秒检查一次 logout.signal
        val scheduler = Executors.newScheduledThreadPool(1)

        scheduler.scheduleAtFixedRate({
            val logoutFile = File("logout.signal")
            if (logoutFile.exists()) {
                println("下线中...")
                triggerShutdown(client)
                scheduler.shutdown() // 任务完成后停止调度器
            }
        }, 0, 5, TimeUnit.SECONDS)

        States.refreshStates()
        client.run()
    }

    private fun triggerShutdown(client: Client) {
        try {
            if (isRunning) {
                isRunning = false
            }
            if (Session.isInitialized()) {
                if (States.isLogged) {
                    client.term()
                }
                Session.free()
            }
            println("下线成功！")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            e.printStackTrace()
        }
        exitProcess(0) // 退出程序
    }
}
