package com.rsplwe.esurfing

import com.rsplwe.esurfing.States.isRunning
import com.rsplwe.esurfing.States.ticket
import com.rsplwe.esurfing.hook.Session
import com.rsplwe.esurfing.network.NetResult
import com.rsplwe.esurfing.network.post
import com.rsplwe.esurfing.utils.ConnectivityStatus.*
import com.rsplwe.esurfing.utils.checkVerifyCodeStatus
import com.rsplwe.esurfing.utils.detectConfig
import com.rsplwe.esurfing.utils.getTime
import com.rsplwe.esurfing.utils.getVerifyCode
import org.apache.log4j.Logger
import org.jsoup.Jsoup
import org.jsoup.parser.Parser
import java.lang.Thread.sleep
import java.net.InetAddress


class Client(private val options: Options) {

    private val logger: Logger = Logger.getLogger(Client::class.java)
    private var keepUrl = ""
    private var termUrl = ""
    private var keepRetry = ""

    @Volatile
    var tick: Long = 0

    init {
        States.userIp = options.userIp
        States.acIp = options.acIp
    }

    fun run() {
        while (isRunning) {
            val networkStatus = detectConfig()
            when (networkStatus) {
                SUCCESS -> {
                    if (Session.isInitialized() && States.isLogged) {
                        try {
                            if ((System.currentTimeMillis() - tick) >= (keepRetry.toLong() * 1000)) {
                                logger.info("Send Keep Packet")
                                heartbeat(ticket)
                                logger.info("Next Retry: $keepRetry")
                                tick = System.currentTimeMillis()
                            }
                        } catch (e: Exception) {
                            logger.info(e.toString())
                            States.isLogged = false
                        }
                    } else {
                        logger.info("The network has been connected.")
                    }
                    sleep(1000)
                }

                REQUIRE_AUTHORIZATION -> {
                    // 获取本机IP并与States.userIp对比
                    val localIp = InetAddress.getLocalHost().hostAddress

                    if (States.userIp != localIp && States.isLogged) {
                        try {
                            if ((System.currentTimeMillis() - tick) >= (keepRetry.toLong() * 1000)) {
                                logger.info("Send Keep Packet")
                                heartbeat(ticket)
                                logger.info("Next Retry: $keepRetry")
                                tick = System.currentTimeMillis()
                            }
                        } catch (e: Exception) {
                            logger.info(e.toString())
                            States.isLogged = false
                        }
                    } else {
                        States.isLogged = false
                        sleep(3000)
                        authorization()
                    }
                }

                REQUEST_ERROR -> {
                    logger.error("Request Error")
                    sleep(5000)
                }
            }
        }
    }

    private fun authorization() {
        val code = options.smsCode.ifBlank { checkSMSVerify() ?: "" }
        if (code.isNotBlank()) {
            println("SMS Code is: $code")
        }


        if (Session.isInitialized()) {
            Session.free()
        }

        States.refreshStates()

        initSession()
        if (Session.getSessionId() == 0.toLong()) {
            logger.error("Failed to initialize session.")
            isRunning = false
            return
        }

        logger.info("Key: ${Session.getKey()}")
        logger.info("Algo Id: ${Session.getAlgoId()}")
        logger.info("Session Id: ${Session.getSessionId()}")
        logger.info("Client IP: ${options.userIp}")
        logger.info("AC IP: ${options.acIp}")

        ticket = getTicket()
        logger.info("Ticket: $ticket")

        login(code)
        if (keepUrl.isEmpty()) {
            logger.error("KeepUrl is empty.")
            Session.free()
            isRunning = false
            return
        }
        tick = System.currentTimeMillis()
        States.isLogged = true
        logger.info("The login has been authorized.")
    }

    private fun checkSMSVerify(): String {
        if (checkVerifyCodeStatus(options.loginUser) && getVerifyCode(options.loginUser)) {
            logger.info("This login requires a SMS verification code.")
            while (true) {
                print("Input Code: ")
                val input = readlnOrNull()
                if (input != null) {
                    val code = input.trim()
                    if (code.isNotBlank()) {
                        return code
                    }
                }
            }
        }
        return ""
    }

    private fun initSession() {
        when (val result = post(States.ticketUrl, States.algoId)) {
            is NetResult.Success -> {
                Session.initialize(result.data.bytes())
            }

            is NetResult.Error -> {
                error("Error: ${result.exception}")
            }
        }
    }

    private fun getTicket(): String {
        val payload = """
            <?xml version="1.0" encoding="utf-8"?>
            <request>
                <user-agent>${Constants.USER_AGENT}</user-agent>
                <client-id>${States.clientId}</client-id>
                <local-time>${getTime()}</local-time>
                <host-name>${Constants.HOST_NAME}</host-name>
                <ipv4>${options.userIp}</ipv4>
                <ipv6></ipv6>
                <mac>${States.macAddress}</mac>
                <ostag>${Constants.HOST_NAME}</ostag>
                <gwip>${States.acIp}</gwip>
            </request>
        """.trimIndent()
        when (val result = post(States.ticketUrl, Session.encrypt(payload))) {
            is NetResult.Success -> {
                val data = Session.decrypt(result.data.string())
                val doc = Jsoup.parse(data, Parser.xmlParser())
                return doc.getElementsByTag("ticket").first()?.text() ?: ""
            }

            is NetResult.Error -> {
                error("Error: ${result.exception}")
            }
        }
    }


    private fun login(code: String = "") {
        val verify = if (code.isBlank()) "" else "<verify>${code}</verify>"
        val payload = """
            <?xml version="1.0" encoding="utf-8"?>
            <request>
                <user-agent>${Constants.USER_AGENT}</user-agent>
                <client-id>${States.clientId}</client-id>
                <ticket>${ticket}</ticket>
                <local-time>${getTime()}</local-time>
                <userid>${options.loginUser}</userid>
                <passwd>${options.loginPassword}</passwd>
                $verify
            </request>
        """.trimIndent()
        when (val result = post(States.authUrl, Session.encrypt(payload))) {
            is NetResult.Success -> {
                val data = Session.decrypt(result.data.string())
                val doc = Jsoup.parse(data, Parser.xmlParser())

                keepUrl = doc.getElementsByTag("keep-url").first()?.text() ?: ""
                termUrl = doc.getElementsByTag("term-url").first()?.text() ?: ""
                keepRetry = doc.getElementsByTag("keep-retry").first()?.text() ?: ""

                logger.info("Keep Url: $keepUrl")
                logger.info("Term Url: $termUrl")
                logger.info("Keep Retry: $keepRetry")
            }

            is NetResult.Error -> {
                error("Error: ${result.exception}")
            }
        }
    }

    private fun heartbeat(ticket: String) {
        val payload = """
        <?xml version="1.0" encoding="utf-8"?>
        <request>
            <user-agent>${Constants.USER_AGENT}</user-agent>
            <client-id>${States.clientId}</client-id>
            <local-time>${getTime()}</local-time>
            <host-name>${Constants.HOST_NAME}</host-name>
            <ipv4>${options.userIp}</ipv4>
            <ticket>${ticket}</ticket>
            <ipv6></ipv6>
            <mac>${States.macAddress}</mac>
            <ostag>${Constants.HOST_NAME}</ostag>
        </request>
    """.trimIndent()
        try {
            when (val result = post(keepUrl, Session.encrypt(payload))) {
                is NetResult.Success -> {
                    val data = Session.decrypt(result.data.string())
                    val doc = Jsoup.parse(data, Parser.xmlParser())
                    keepRetry = doc.getElementsByTag("interval").first()?.text() ?: ""
                }

                is NetResult.Error -> {
                    error("Error: ${result.exception}")
                }
            }
        } catch (e: Exception) {
            // 捕获任何异常（如网络超时、连接失败等），并将间隔设为 480
            logger.error("Heartbeat request failed: ${e.message}")
            keepRetry = "480"  // 设置默认间隔为 480
        }
    }


    fun term() {
        val payload = """
            <?xml version="1.0" encoding="utf-8"?>
            <request>
                <user-agent>${Constants.USER_AGENT}</user-agent>
                <client-id>${States.clientId}</client-id>
                <local-time>${getTime()}</local-time>
                <host-name>${Constants.HOST_NAME}</host-name>
                <ipv4>${options.userIp}</ipv4>
                <ticket>${ticket}</ticket>
                <ipv6></ipv6>
                <mac>${States.macAddress}</mac>
                <ostag>${Constants.HOST_NAME}</ostag>
            </request>
        """.trimIndent()
        when (val result = post(termUrl, Session.encrypt(payload))) {
            is NetResult.Success -> {}
            is NetResult.Error -> {
                error("Error: ${result.exception}")
            }
        }
    }
}
