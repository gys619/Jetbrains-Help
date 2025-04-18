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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Slf4j(topic = "代理上下文")
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AgentContextHolder {

    private static final String JA_NETFILTER_FILE_PATH = "external/agent/ja-netfilter";

    private static final String POWER_CONF_FILE_NAME = JA_NETFILTER_FILE_PATH + "/config-jetbrains/power.conf";
    
    // 可能的配置文件名
    private static final String[] POSSIBLE_CONFIG_FILES = {"power.conf", "power.txt"};

    private static File jaNetfilterFile;

    private static File jaNetfilterZipFile;
    
    // 实际的config-jetbrains目录和power.conf文件路径
    private static File actualConfigDir;
    private static File actualPowerConfFile;

    public static void init() {
        log.info("初始化中...");
        try {
            jaNetfilterZipFile = FileTools.getFileOrCreat(JA_NETFILTER_FILE_PATH + ".zip");
            
            // 检查目标目录
            File targetDir = FileTools.getFile(JA_NETFILTER_FILE_PATH);
            log.info("目标目录路径: {}, 是否存在: {}", targetDir.getAbsolutePath(), targetDir.exists());
            
            // 尝试定位实际的配置文件
            findActualConfigPaths(targetDir);
            
            // 如果目标目录不存在或配置文件不存在，则进行解压和初始化
            if (!targetDir.exists() || actualPowerConfFile == null || !actualPowerConfFile.exists()) {
                log.info("目标目录或配置文件不存在，执行解压操作");
                unzipJaNetfilter();
                
                if (!powerConfHasInit()) {
                    log.info("配置初始化中...");
                    loadPowerConf();
                    zipJaNetfilter();
                    log.info("配置初始化成功!");
                }
            } else {
                log.info("目标目录和配置文件已存在");
                jaNetfilterFile = findJaNetfilterRootDir(targetDir);
            }
            log.info("初始化成功!");
        } catch (Exception e) {
            log.error("初始化过程中发生错误", e);
            throw e;
        }
    }

    public static File jaNetfilterZipFile() {
        return AgentContextHolder.jaNetfilterZipFile;
    }

    private static boolean powerConfHasInit() {
        // 如果actualPowerConfFile为null，则使用默认路径
        File powerConfFile = actualPowerConfFile != null ? actualPowerConfFile : FileTools.getFileOrCreat(POWER_CONF_FILE_NAME);
        
        log.info("检查配置文件初始化状态: {}", powerConfFile.getAbsolutePath());
        
        if (!powerConfFile.exists()) {
            log.warn("配置文件不存在: {}", powerConfFile.getAbsolutePath());
            return false;
        }
        
        String powerConfStr;
        try {
            powerConfStr = IoUtil.readUtf8(FileUtil.getInputStream(powerConfFile));
            log.info("配置文件内容: {}", powerConfStr);
            return CharSequenceUtil.containsAll(powerConfStr, "[Result]", "EQUAL,");
        } catch (IORuntimeException e) {
            log.error("配置文件读取失败，路径: {}, 错误原因: {}", powerConfFile.getAbsolutePath(), e.getMessage(), e);
            // 不立即抛出异常，返回false表示初始化未完成
            return false;
        }
    }

    private static void loadPowerConf() {
        CompletableFuture
                .supplyAsync(AgentContextHolder::generatePowerConfigRule)
                .thenApply(AgentContextHolder::generatePowerConfigStr)
                .thenAccept(AgentContextHolder::overridePowerConfFileContent)
                .exceptionally(throwable -> {
                    log.error("配置初始化失败!", throwable);
                    return null;
                }).join();
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
        // 使用实际找到的配置文件路径，如果未找到则使用默认路径
        File powerConfFile = actualPowerConfFile != null ? actualPowerConfFile : FileTools.getFileOrCreat(POWER_CONF_FILE_NAME);
        log.info("准备写入配置文件: {}", powerConfFile.getAbsolutePath());
        
        try {
            // 确保配置文件的父目录存在
            File parentDir = powerConfFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                boolean created = parentDir.mkdirs();
                log.info("创建父目录: {}, 结果: {}", parentDir.getAbsolutePath(), created ? "成功" : "失败");
                if (!created) {
                    log.warn("创建目录失败: {}", parentDir.getAbsolutePath());
                }
            }
            
            FileUtil.writeString(configStr, powerConfFile, StandardCharsets.UTF_8);
            log.info("配置文件写入成功，文件路径: {}, 文件是否存在: {}", 
                     powerConfFile.getAbsolutePath(), powerConfFile.exists());
        } catch (IORuntimeException e) {
            log.error("配置文件写入失败，路径: {}, 错误原因: {}", powerConfFile.getAbsolutePath(), e.getMessage(), e);
            throw new IllegalArgumentException(CharSequenceUtil.format("{} 文件写入失败!", powerConfFile.getAbsolutePath()), e);
        }
    }

    private static void unzipJaNetfilter() {
        try {
            log.info("开始解压 ja-netfilter.zip 到 {}", JA_NETFILTER_FILE_PATH);
            
            // 确保目标目录存在
            File targetDir = FileTools.getFile(JA_NETFILTER_FILE_PATH);
            if (!targetDir.exists()) {
                boolean created = targetDir.mkdirs();
                log.info("创建目标目录: {}, 结果: {}", targetDir.getAbsolutePath(), created ? "成功" : "失败");
                if (!created) {
                    log.warn("创建目录失败: {}", targetDir.getAbsolutePath());
                }
            }
            
            // 指定解压目标目录
            File extractedDir = ZipUtil.unzip(jaNetfilterZipFile, targetDir);
            log.info("解压完成，文件路径: {}", extractedDir.getAbsolutePath());
            
            // 验证解压后的文件结构并确定实际根目录
            jaNetfilterFile = findJaNetfilterRootDir(targetDir);
            log.info("找到ja-netfilter实际根目录: {}", jaNetfilterFile.getAbsolutePath());
            
            // 寻找config-jetbrains目录和power.conf文件
            findActualConfigPaths(jaNetfilterFile);
            
            // 打印文件结构以验证
            if (jaNetfilterFile != null && jaNetfilterFile.exists()) {
                logDirectoryContents(jaNetfilterFile);
            }
        } catch (Exception e) {
            log.error("解压文件时发生错误: {}", e.getMessage(), e);
            throw new RuntimeException("解压 ja-netfilter.zip 失败", e);
        }
    }
    
    /**
     * 查找实际的ja-netfilter根目录
     * 处理可能的嵌套目录结构
     */
    private static File findJaNetfilterRootDir(File baseDir) {
        if (baseDir == null || !baseDir.exists() || !baseDir.isDirectory()) {
            return baseDir;
        }
        
        // 检查是否有嵌套的ja-netfilter目录
        File nestedJaNetfilterDir = new File(baseDir, "ja-netfilter");
        if (nestedJaNetfilterDir.exists() && nestedJaNetfilterDir.isDirectory()) {
            log.info("检测到嵌套的ja-netfilter目录: {}", nestedJaNetfilterDir.getAbsolutePath());
            return nestedJaNetfilterDir;
        }
        
        return baseDir;
    }
    
    /**
     * 寻找实际的config-jetbrains目录和power.conf文件
     */
    private static void findActualConfigPaths(File baseDir) {
        if (baseDir == null || !baseDir.exists() || !baseDir.isDirectory()) {
            log.warn("基础目录不存在或不是目录: {}", baseDir != null ? baseDir.getAbsolutePath() : "null");
            return;
        }
        
        log.info("开始搜索配置目录和文件，基础目录: {}", baseDir.getAbsolutePath());
        
        // 首先尝试预期路径
        File expectedConfigDir = new File(baseDir, "config-jetbrains");
        if (checkConfigDir(expectedConfigDir)) {
            return;
        }
        
        // 如果预期路径不存在，尝试在嵌套的ja-netfilter目录中查找
        File nestedDir = new File(baseDir, "ja-netfilter");
        if (nestedDir.exists() && nestedDir.isDirectory()) {
            File nestedConfigDir = new File(nestedDir, "config-jetbrains");
            if (checkConfigDir(nestedConfigDir)) {
                return;
            }
        }
        
        // 最后广泛搜索所有可能的配置目录
        List<File> configDirs = findConfigDirectories(baseDir);
        log.info("找到 {} 个可能的配置目录", configDirs.size());
        
        for (File configDir : configDirs) {
            if (checkConfigDir(configDir)) {
                log.info("从搜索结果中找到有效的配置目录: {}", configDir.getAbsolutePath());
                return;
            }
        }
        
        log.warn("未能找到任何有效的配置目录和配置文件");
        actualConfigDir = null;
        actualPowerConfFile = null;
    }
    
    /**
     * 检查目录是否为有效的配置目录（包含power.conf文件）
     * @return 如果是有效的配置目录则返回true
     */
    private static boolean checkConfigDir(File configDir) {
        if (configDir != null && configDir.exists() && configDir.isDirectory()) {
            log.info("检查可能的配置目录: {}", configDir.getAbsolutePath());
            
            // 检查所有可能的配置文件名
            for (String configFileName : POSSIBLE_CONFIG_FILES) {
                File configFile = new File(configDir, configFileName);
                if (configFile.exists()) {
                    log.info("找到有效的配置文件: {}", configFile.getAbsolutePath());
                    actualConfigDir = configDir;
                    actualPowerConfFile = configFile;
                    return true;
                }
            }
            
            // 记录目录内容，帮助调试
            log.info("配置目录存在但未找到配置文件，列出目录内容:");
            logDirectoryContents(configDir);
        }
        return false;
    }
    
    /**
     * 查找所有可能的配置目录
     * 包括config-jetbrains、config目录以及包含config的目录
     */
    private static List<File> findConfigDirectories(File baseDir) {
        List<File> results = new ArrayList<>();
        if (baseDir == null || !baseDir.exists() || !baseDir.isDirectory()) {
            return results;
        }
        
        // 使用辅助方法递归搜索所有可能的配置目录
        findAllConfigDirs(baseDir, results);
        
        // 对结果按优先级排序：
        // 1. 精确匹配"config-jetbrains"
        // 2. 精确匹配"config"
        // 3. 包含"config"的其他目录（按字母顺序）
        results.sort(Comparator.<File>comparingInt(file -> {
            String name = file.getName().toLowerCase();
            if (name.equals("config-jetbrains")) return 0;
            else if (name.equals("config")) return 1;
            else return 2;
        }).thenComparing(File::getName));
        
        // 打印找到的所有配置目录
        if (!results.isEmpty()) {
            log.info("找到的可能配置目录（按优先级排序）:");
            for (int i = 0; i < results.size(); i++) {
                log.info("{}. {}", i + 1, results.get(i).getAbsolutePath());
            }
        }
        
        return results;
    }
    
    /**
     * 递归查找所有可能的配置目录
     */
    private static void findAllConfigDirs(File dir, List<File> results) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) {
            return;
        }
        
        // 检查当前目录是否为可能的配置目录
        String dirName = dir.getName().toLowerCase();
        if (dirName.equals("config-jetbrains") || dirName.equals("config") || dirName.contains("config")) {
            results.add(dir);
        }
        
        // 递归检查子目录
        File[] subDirs = dir.listFiles(File::isDirectory);
        if (subDirs != null) {
            for (File subDir : subDirs) {
                findAllConfigDirs(subDir, results);
            }
        }
    }
    
    /**
     * 递归查找指定名称的目录
     */
    private static File findDirectoryRecursively(File baseDir, String dirName) {
        if (baseDir == null || !baseDir.exists() || !baseDir.isDirectory()) {
            return null;
        }
        
        // 检查当前目录是否为目标目录
        if (baseDir.getName().equals(dirName)) {
            return baseDir;
        }
        
        // 遍历子目录
        File[] subDirs = baseDir.listFiles(File::isDirectory);
        if (subDirs != null) {
            for (File subDir : subDirs) {
                // 检查子目录是否为目标目录
                if (subDir.getName().equals(dirName)) {
                    return subDir;
                }
                
                // 递归检查子目录的子目录
                File result = findDirectoryRecursively(subDir, dirName);
                if (result != null) {
                    return result;
                }
            }
        }
        
        return null;
    }

    private static void zipJaNetfilter() {
        try {
            // 确保使用正确的根目录进行压缩
            File dirToZip = jaNetfilterFile != null ? jaNetfilterFile : FileTools.getFile(JA_NETFILTER_FILE_PATH);
            jaNetfilterZipFile = ZipUtil.zip(dirToZip);
            log.info("压缩完成，文件路径: {}", jaNetfilterZipFile.getAbsolutePath());
        } catch (Exception e) {
            log.error("压缩文件时发生错误: {}", e.getMessage(), e);
            throw new RuntimeException("压缩 ja-netfilter 目录失败", e);
        }
    }
    
    /**
     * 记录目录内容
     */
    private static void logDirectoryContents(File directory) {
        if (directory == null || !directory.exists() || !directory.isDirectory()) {
            return;
        }
        
        File[] files = directory.listFiles();
        if (files == null || files.length == 0) {
            log.info("目录为空: {}", directory.getAbsolutePath());
            return;
        }
        
        log.info("目录内容 - {}", directory.getAbsolutePath());
        for (File file : files) {
            log.info("  - {} ({})", file.getName(), file.isDirectory() ? "目录" : "文件");
            // 如果是directory且层级不太深，递归列出子目录
            if (file.isDirectory() && file.getAbsolutePath().split(File.separator).length < 12) {
                logDirectoryContents(file);
            }
        }
    }
}
