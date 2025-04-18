package com.jetbrains.help.context;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IORuntimeException;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.text.CharSequenceUtil;
import cn.hutool.core.util.ZipUtil;
import cn.hutool.crypto.KeyUtil;
import cn.hutool.crypto.PemUtil;
import com.jetbrains.help.util.FileTools;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.CompletableFuture;

@Slf4j(topic = "代理上下文")
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AgentContextHolder {

    private static final String JA_NETFILTER_FILE_PATH = "external/agent/ja-netfilter";

    private static final String POWER_CONF_FILE_NAME = JA_NETFILTER_FILE_PATH + "/config-jetbrains/power.conf";

    private static File jaNetfilterFile;

    private static File jaNetfilterZipFile;

    public static void init() {
        log.info("初始化中...");
        // 确保zip文件存在
        jaNetfilterZipFile = FileTools.getFileOrCreat(JA_NETFILTER_FILE_PATH + ".zip");
        
        // 确保目录结构存在
        ensureDirectoryStructure();
        
        if (!FileTools.fileExists(JA_NETFILTER_FILE_PATH)) {
            try {
                unzipJaNetfilter();
                log.info("解压ja-netfilter成功");
            } catch (Exception e) {
                log.error("解压ja-netfilter失败", e);
                // 创建必要的目录结构
                createDirectoryStructure();
            }
        }
        
        if (!powerConfHasInit()) {
            log.info("配置初始化中...");
            loadPowerConf();
            zipJaNetfilter();
            log.info("配置初始化成功!");
        }
        
        log.info("初始化成功!");
    }

    private static void ensureDirectoryStructure() {
        // 确保主目录存在
        File mainDir = new File(JA_NETFILTER_FILE_PATH);
        if (!mainDir.exists()) {
            mainDir.mkdirs();
        }
        
        // 确保config目录存在
        File configDir = new File(JA_NETFILTER_FILE_PATH + "/config-jetbrains");
        if (!configDir.exists()) {
            configDir.mkdirs();
        }
    }
    
    private static void createDirectoryStructure() {
        ensureDirectoryStructure();
        // 这里可以添加创建其他必要文件的逻辑
    }

    public static File jaNetfilterZipFile() {
        return AgentContextHolder.jaNetfilterZipFile;
    }

    private static boolean powerConfHasInit() {
        File powerConfFile = FileTools.getFileOrCreat(POWER_CONF_FILE_NAME);
        
        // 先检查文件是否存在并且有内容
        if (!powerConfFile.exists() || powerConfFile.length() == 0) {
            log.warn("power.conf文件不存在或为空，将尝试创建默认配置");
            try {
                // 创建一个默认的配置
                return false; // 返回false以触发loadPowerConf()
            } catch (Exception e) {
                log.error("创建默认配置文件失败", e);
                return false;
            }
        }
        
        String powerConfStr;
        try {
            powerConfStr = IoUtil.readUtf8(FileUtil.getInputStream(powerConfFile));
        } catch (IORuntimeException e) {
            log.error("power.conf文件读取失败，将尝试重新创建", e);
            return false; // 返回false以触发loadPowerConf()
        }
        log.info("写入power.conf");
        return CharSequenceUtil.containsAll(powerConfStr, "[Result]", "EQUAL,");
    }

    private static void loadPowerConf() {
        int retryCount = 0;
        int maxRetries = 3;
        boolean success = false;
        
        while (!success && retryCount < maxRetries) {
            try {
                int finalRetryCount = retryCount;
                CompletableFuture
                    .supplyAsync(AgentContextHolder::generatePowerConfigRule)
                    .thenApply(AgentContextHolder::generatePowerConfigStr)
                    .thenAccept(AgentContextHolder::overridePowerConfFileContent)
                    .exceptionally(throwable -> {
                        log.error("配置初始化失败! 尝试次数: {}", finalRetryCount + 1, throwable);
                        return null;
                    }).join();
                
                // 检查是否成功创建
                File powerConfFile = new File(POWER_CONF_FILE_NAME);
                if (powerConfFile.exists() && powerConfFile.length() > 0) {
                    success = true;
                }
            } catch (Exception e) {
                log.error("配置加载过程中发生错误，尝试次数: {}", retryCount + 1, e);
            }
            
            retryCount++;
            if (!success && retryCount < maxRetries) {
                try {
                    Thread.sleep(1000); // 等待1秒后重试
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        if (!success) {
            log.error("多次尝试初始化配置失败，请检查系统环境和文件权限");
        }
    }

    @SneakyThrows
    private static String generatePowerConfigRule() {
        X509Certificate crt = (X509Certificate) KeyUtil.readX509Certificate(IoUtil.toStream(CertificateContextHolder.crtFile()));
        RSAPublicKey publicKey = (RSAPublicKey) PemUtil.readPemPublicKey(IoUtil.toStream(CertificateContextHolder.publicKeyFile()));
        RSAPublicKey rootPublicKey = (RSAPublicKey) PemUtil.readPemPublicKey(IoUtil.toStream(CertificateContextHolder.rootKeyFile()));
        BigInteger x = new BigInteger(1, crt.getSignature());
        BigInteger y = BigInteger.valueOf(65537L);
        BigInteger z = rootPublicKey.getModulus();
        BigInteger r = x.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        return CharSequenceUtil.format("EQUAL,{},{},{}->{}", x, y, z, r);
    }

    private static String generatePowerConfigStr(String ruleValue) {
        return CharSequenceUtil.builder("[Result]", "\n", ruleValue).toString();
    }

    private static void overridePowerConfFileContent(String configStr) {
        File powerConfFile = FileTools.getFileOrCreat(POWER_CONF_FILE_NAME);
        try {
            FileUtil.writeString(configStr, powerConfFile, StandardCharsets.UTF_8);
        } catch (IORuntimeException e) {
            log.error("power.conf文件写入失败", e);
            throw new IllegalArgumentException(CharSequenceUtil.format("{} 文件写入失败!", POWER_CONF_FILE_NAME), e);
        }
    }

    private static void unzipJaNetfilter() {
        jaNetfilterFile = ZipUtil.unzip(jaNetfilterZipFile);
    }

    private static void zipJaNetfilter() {
        jaNetfilterZipFile = ZipUtil.zip(jaNetfilterFile);
    }
}
