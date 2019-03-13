/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.server;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.zeppelin.server.SmartZeppelinServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;
import org.smartdata.SmartServiceState;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.hdfs.HadoopUtil;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.utils.MetaStoreUtils;
import org.smartdata.server.engine.CmdletManager;
import org.smartdata.server.engine.ConfManager;
import org.smartdata.server.engine.RuleManager;
import org.smartdata.server.engine.ServerContext;
import org.smartdata.server.engine.ServiceMode;
import org.smartdata.server.engine.StatesManager;
import org.smartdata.server.engine.cmdlet.agent.AgentMaster;
import org.smartdata.server.utils.GenericOptionsParser;
import org.smartdata.utils.SecurityUtil;
import static org.smartdata.SmartConstants.NUMBER_OF_SMART_AGENT;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * From this Smart Storage Management begins.
 */
public class SmartServer {
  public static final Logger LOG = LoggerFactory.getLogger(SmartServer.class);

  private ConfManager confMgr;
  private final SmartConf conf;
  private SmartEngine engine;
  private ServerContext context;
  private boolean enabled;

  private SmartRpcServer rpcServer;
  private SmartZeppelinServer zeppelinServer;

  static {
    SLF4JBridgeHandler.removeHandlersForRootLogger();
    SLF4JBridgeHandler.install();
  }

  // SmartServer实例化
  public SmartServer(SmartConf conf) {
    this.conf = conf;
    this.confMgr = new ConfManager(conf);
    this.enabled = false;
  }

  // 初始化各模块（MetaStoreSmartEngine、RpcServer、ZeppelinServer、ServletContext）
  public void initWith() throws Exception {
    LOG.info("Start Init Smart Server");

    // 读取Hadoop配置项
    HadoopUtil.setSmartConfByHadoop(conf);
    // 进行Kerberos授权，如果关闭了授权配置则直接return
    authentication();
    // 获得MetaStore对象，MetaStore实现了数据库的各种操作，并且实例化了各种Dao层。
    MetaStore metaStore = MetaStoreUtils.getDBAdapter(conf);
    // ServerContext继承了SmartContext，拥有父类获取SmartConf的能力，并且拓展了父类功能。
    // 增加了可以获得MetaStore和ServerMode（枚举型，支持HDFS和ALLUXIO）的功能。
    context = new ServerContext(conf, metaStore);
    // 初始化服务模式标识，默认是基于HDFS
    initServiceMode(conf);
    // 通过ServerContext实例化SmartEngine
    engine = new SmartEngine(context);
    // 通过SmartServer对象，实例化SmartRpcServer
    rpcServer = new SmartRpcServer(this, conf);
    zeppelinServer = new SmartZeppelinServer(conf, engine);

    LOG.info("Finish Init Smart Server");
  }

  public StatesManager getStatesManager() {
    return engine.getStatesManager();
  }

  public RuleManager getRuleManager() {
    return engine.getRuleManager();
  }

  public CmdletManager getCmdletManager() {
    return engine.getCmdletManager();
  }

  public MetaStore getMetaStore() {
    return this.context.getMetaStore();
  }

  public ServerContext getContext() {
    return this.context;
  }

  public static StartupOption processArgs(String[] args, SmartConf conf) throws Exception {
    if (args == null) {
      args = new String[0];
    }

    StartupOption startOpt = StartupOption.REGULAR;
    List<String> list = new ArrayList<>();
    for (String arg : args) {
      if (StartupOption.FORMAT.getName().equalsIgnoreCase(arg)) {
        startOpt = StartupOption.FORMAT;
      } else if (StartupOption.REGULAR.getName().equalsIgnoreCase(arg)) {
        startOpt = StartupOption.REGULAR;
      } else if (arg.equals("-h") || arg.equals("-help")) {
        if (parseHelpArgument(new String[]{arg}, USAGE, System.out, true)) {
          return null;
        }
      } else {
        list.add(arg);
      }
    }
    if (list != null) {
      String remainArgs[] = list.toArray(new String[list.size()]);
      new GenericOptionsParser(conf, remainArgs);
    }

    return startOpt;
  }

  public static void setAgentNum(SmartConf conf) {
    String agentConfFile = conf.get(SmartConfKeys.SMART_CONF_DIR_KEY,
        SmartConfKeys.SMART_CONF_DIR_DEFAULT) + "/agents";
    Scanner sc = null;
    try {
      sc = new Scanner(new File(agentConfFile));
    } catch (FileNotFoundException ex) {
      LOG.error("Cannot find the config file: {}!", agentConfFile);
    }
    int num = 0;
    while (sc.hasNextLine()) {
      String host = sc.nextLine().trim();
      if (!host.startsWith("#") && !host.isEmpty()) {
        num++;
      }
    }
    conf.setInt(NUMBER_OF_SMART_AGENT, num);
  }

  static SmartServer processWith(StartupOption startOption, SmartConf conf) throws Exception {
    // New AgentMaster
    AgentMaster.getAgentMaster(conf);

    if (startOption == StartupOption.FORMAT) {
      LOG.info("Formatting DataBase ...");
      MetaStoreUtils.formatDatabase(conf);
      LOG.info("Formatting DataBase finished successfully!");
    } else {
      MetaStoreUtils.checkTables(conf);
    }

    // 实例化SmartServer
    SmartServer ssm = new SmartServer(conf);
    try {
      // 初始化SmartServer相关模块（MetaStoreSmartEngine、RpcServer、ZeppelinServer、ServletContext）
      ssm.initWith();
      // 运行SmartServer相关模块（ZeppelinServer、RpcServer）
      ssm.run();
      return ssm;
    } catch (Exception e) {
      ssm.shutdown();
      throw e;
    }
  }

  private static final String USAGE =
      "Usage: ssm [options]\n"
          + "  -h\n\tShow this usage information.\n\n"
          + "  -format\n\tFormat the configured database.\n\n"
          + "  -D property=value\n"
          + "\tSpecify or overwrite an configure option.\n"
          + "\tE.g. -D smart.dfs.namenode.rpcserver=hdfs://localhost:43543\n";

  private static final Options helpOptions = new Options();
  private static final Option helpOpt = new Option("h", "help", false,
      "get help information");

  static {
    helpOptions.addOption(helpOpt);
  }

  private static boolean parseHelpArgument(String[] args,
    String helpDescription, PrintStream out, boolean printGenericCmdletUsage) {
    try {
      CommandLineParser parser = new PosixParser();
      CommandLine cmdLine = parser.parse(helpOptions, args);
      if (cmdLine.hasOption(helpOpt.getOpt())
          || cmdLine.hasOption(helpOpt.getLongOpt())) {
        // should print out the help information
        out.println(helpDescription + "\n");
        return true;
      }
    } catch (ParseException pe) {
      //LOG.warn("Parse help exception", pe);
      return false;
    }
    return false;
  }

  // Kerberos授权
  private void authentication() throws IOException {
    // 如果安全认证未开启，则不再执行下面授权部分。
    if (!SecurityUtil.isSecurityEnabled(conf)) {
      return;
    }

    // 从conf中读取所有hadoop配置
    try {
      HadoopUtil.loadHadoopConf(conf);
    } catch (IOException e) {
      LOG.info("Running in secure mode, but cannot find Hadoop configuration file. "
          + "Please config smart.hadoop.conf.path property in smart-site.xml.");
      conf.set("hadoop.security.authentication", "kerberos");
      conf.set("hadoop.security.authorization", "true");
    }

    // 配置Kerberos相关信息
    UserGroupInformation.setConfiguration(conf);

    // 获取用户keytab
    String keytabFilename = conf.get(SmartConfKeys.SMART_SERVER_KEYTAB_FILE_KEY);
    // 下面两行获取登录用户
    String principalConfig = conf.get(SmartConfKeys.SMART_SERVER_KERBEROS_PRINCIPAL_KEY);
    String principal =
        org.apache.hadoop.security.SecurityUtil.getServerPrincipal(principalConfig, (String) null);

    // 使用用户名和用户秘钥登录
    SecurityUtil.loginUsingKeytab(keytabFilename, principal);
  }

  /**
   * Bring up all the daemon threads needed.
   *
   * @throws Exception
   */
  private void run() throws Exception {
    // DFS是否开启标志，默认开启
    boolean enabled = conf.getBoolean(SmartConfKeys.SMART_DFS_ENABLED,
        SmartConfKeys.SMART_DFS_ENABLED_DEFAULT);

    // 如果DFS开启，则启动SmartEngine
    if (enabled) {
      startEngines();
    }

    // 开启RpcServer
    rpcServer.start();

    // 如果ZeppelinServer已经实例化，则开启ZeppelinServer
    if (zeppelinServer != null) {
      zeppelinServer.start();
    }
  }

  private void startEngines() throws Exception {
    enabled = true;
    engine.init();
    engine.start();
  }

  public void enable() throws IOException {
    if (getSSMServiceState() == SmartServiceState.DISABLED) {
      try {
        startEngines();
      } catch (Exception e) {
        throw new IOException(e);
      }
    }
  }

  public SmartServiceState getSSMServiceState() {
    if (!enabled) {
      return SmartServiceState.DISABLED;
    } else if (!engine.inSafeMode()) {
      return SmartServiceState.ACTIVE;
    } else {
      return SmartServiceState.SAFEMODE;
    }
  }

  public boolean isActive() {
    return getSSMServiceState() == SmartServiceState.ACTIVE;
  }

  private void stop() throws Exception {
    if (engine != null) {
      engine.stop();
    }

    if (zeppelinServer != null) {
      zeppelinServer.stop();
    }

    try {
      if (rpcServer != null) {
        rpcServer.stop();
      }
    } catch (Exception e) {
    }
  }

  public void shutdown() {
    try {
      stop();
      //join();
    } catch (Exception e) {
      LOG.error("SmartServer shutdown error", e);
    }
  }

  private enum StartupOption {
    FORMAT("-format"),
    REGULAR("-regular");

    private String name;

    StartupOption(String arg) {
      this.name = arg;
    }

    public String getName() {
      return name;
    }
  }

  // 初始化服务模式
  private void initServiceMode(SmartConf conf) {
    // 获取配置的服务模式，默认是HDFS
    String serviceModeStr = conf.get(SmartConfKeys.SMART_SERVICE_MODE_KEY,
        SmartConfKeys.SMART_SERVICE_MODE_DEFAULT);
    try {
      // 设置ServerContext中的服务模式
      context.setServiceMode(ServiceMode.valueOf(serviceModeStr.trim().toUpperCase()));
    } catch (IllegalStateException e) {
      String errorMsg =
          "Illegal service mode '"
              + serviceModeStr
              + "' set in property: "
              + SmartConfKeys.SMART_SERVICE_MODE_KEY
              + "!";
      LOG.error(errorMsg);
      throw e;
    }
    LOG.info("Initialized service mode: " + context.getServiceMode().getName() + ".");
  }

  public static SmartServer launchWith(SmartConf conf) throws Exception {
    return launchWith(null, conf);
  }

  public static SmartServer launchWith(String[] args, SmartConf conf) throws Exception {
    if (conf == null) {
      conf = new SmartConf();
    }

    StartupOption startOption = processArgs(args, conf);
    if (startOption == null) {
      return null;
    }
    return processWith(startOption, conf);
  }

  // SmartServer 入口
  public static void main(String[] args) {
    int errorCode = 0;  // if SSM exit normally then the errorCode is 0
    try {
      final SmartServer inst = launchWith(args, null);
      if (inst != null) {
        Runtime.getRuntime().addShutdownHook(new Thread() {
          @Override
          public void run() {
            LOG.info("Shutting down SmartServer ... ");
            try {
              inst.shutdown();
            } catch (Exception e) {
              LOG.error("Error while stopping servlet container", e);
            }
            LOG.info("SmartServer was down.");
          }
        });
        //Todo: when to break
        while (true) {
          Thread.sleep(1000);
        }
      }
    } catch (Exception e) {
      LOG.error("Failed to create SmartServer", e);
      System.exit(1);
    } finally {
      System.exit(errorCode);
    }
  }
}
