/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zeppelin.server;

import com.sun.jersey.api.core.ApplicationAdapter;
import com.sun.jersey.api.core.ResourceConfig;
import com.sun.jersey.spi.container.servlet.ServletContainer;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.conf.ZeppelinConfiguration.ConfVars;
import org.apache.zeppelin.dep.DependencyResolver;
import org.apache.zeppelin.helium.Helium;
import org.apache.zeppelin.helium.HeliumApplicationFactory;
import org.apache.zeppelin.helium.HeliumVisualizationFactory;
import org.apache.zeppelin.interpreter.InterpreterFactory;
import org.apache.zeppelin.interpreter.InterpreterOption;
import org.apache.zeppelin.interpreter.InterpreterOutput;
import org.apache.zeppelin.interpreter.InterpreterSettingManager;
import org.apache.zeppelin.notebook.Notebook;
import org.apache.zeppelin.notebook.NotebookAuthorization;
import org.apache.zeppelin.rest.CredentialRestApi;
import org.apache.zeppelin.rest.HeliumRestApi;
import org.apache.zeppelin.rest.LoginRestApi;
import org.apache.zeppelin.rest.SecurityRestApi;
import org.apache.zeppelin.rest.ZeppelinRestApi;
import org.apache.zeppelin.scheduler.SchedulerFactory;
import org.apache.zeppelin.search.LuceneSearch;
import org.apache.zeppelin.search.SearchService;
import org.apache.zeppelin.user.Credentials;
import org.apache.zeppelin.utils.SecurityUtils;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.webapp.WebAppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.server.SmartEngine;
import org.smartdata.server.rest.*;

import javax.servlet.DispatcherType;
import javax.ws.rs.core.Application;
import java.io.File;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

/**
 * Main class of embedded Zeppelin Server.
 */
public class SmartZeppelinServer {
  private static final Logger LOG = LoggerFactory.getLogger(SmartZeppelinServer.class);
  private static final String SMART_PATH_SPEC = "/smart/api/v1/*";
  private static final String ZEPPELIN_PATH_SPEC = "/api/*";

  private static SmartEngine engine;
  private SmartConf conf;

  public static Notebook notebook;
  private ZeppelinConfiguration zconf;
  private Server jettyWebServer;
  private Helium helium;

  private InterpreterSettingManager interpreterSettingManager;
  private SchedulerFactory schedulerFactory;
  private InterpreterFactory replFactory;
  private SearchService noteSearchService;
  private NotebookAuthorization notebookAuthorization;
  private Credentials credentials;
  private DependencyResolver depResolver;

  public static SmartEngine getEngine() {
    return engine;
  }

  public SmartZeppelinServer() {}

  // 根据配置文件配置server
  public SmartZeppelinServer(SmartConf conf, SmartEngine engine) throws Exception {
    this.conf = conf;
    // 如果是从main函数实例化SmartZeepelinServer，这里的engine为null【
    this.engine = engine;
    // 创建Zeeplein配置对象，其中已包含默认的zeppelin配置
    this.zconf = ZeppelinConfiguration.create();

    // 获得server地址，默认监听0.0.0.0:7045
    String httpAddr = conf.get(SmartConfKeys.SMART_SERVER_HTTP_ADDRESS_KEY,
        SmartConfKeys.SMART_SERVER_HTTP_ADDRESS_DEFAULT);
    String[] ipport = httpAddr.split(":");
    // 根据已经获得的server地址配置项，设置zeppelin
    System.setProperty(ConfVars.ZEPPELIN_ADDR.getVarName(), ipport[0]);
    System.setProperty(ConfVars.ZEPPELIN_PORT.getVarName(), ipport[1]);

    // 读取日志文件夹配置
    String logDir = conf.get(SmartConfKeys.SMART_LOG_DIR_KEY, SmartConfKeys.SMART_LOG_DIR_DEFAULT);
    String zeppelinLogFile = logDir + "/zeppelin.log";
    // 根据以上读取配置，设置zeppelin日志文件夹
    System.setProperty("zeppelin.log.file", zeppelinLogFile);

    // 设置conf配置目录
    System.setProperty(ConfVars.ZEPPELIN_CONF_DIR.getVarName(),
        conf.get(SmartConfKeys.SMART_CONF_DIR_KEY, SmartConfKeys.SMART_CONF_DIR_DEFAULT));

    // 设置zeppelin home
    if (!isBinaryPackage(zconf)) {
      System.setProperty(ConfVars.ZEPPELIN_HOME.getVarName(), "smart-zeppelin/");
    }
  }

  // 初始化
  private void init() throws Exception {
      // 这里是原Zeppelin的配置，与interpreter相关，因为ssm没有用到interpreter，所以按下不表。
    this.depResolver = new DependencyResolver(
        zconf.getString(ConfVars.ZEPPELIN_INTERPRETER_LOCALREPO));
      // 这里是原Zeppelin的配置，与interpreter相关，因为ssm没有用到interpreter，所以按下不表。
    InterpreterOutput.limit = zconf.getInt(ConfVars.ZEPPELIN_INTERPRETER_OUTPUT_LIMIT);

    // 实例化Helium工厂。Helium是Zeppelin的可视化模块。按下不表。
    HeliumApplicationFactory heliumApplicationFactory = new HeliumApplicationFactory();
    HeliumVisualizationFactory heliumVisualizationFactory;

    // Helium相关配置，用于将前端可视化与后端数据绑定。属于Zeppelin原生代码，所以按下不表
    if (isBinaryPackage(zconf)) {
      /* In binary package, zeppelin-web/src/app/visualization and zeppelin-web/src/app/tabledata
       * are copied to lib/node_modules/zeppelin-vis, lib/node_modules/zeppelin-tabledata directory.
       * Check zeppelin/zeppelin-distribution/src/assemble/distribution.xml to see how they're
       * packaged into binary package.
       */
      heliumVisualizationFactory = new HeliumVisualizationFactory(
          zconf,
          new File(zconf.getRelativeDir(ConfVars.ZEPPELIN_DEP_LOCALREPO)),
          new File(zconf.getRelativeDir("lib/node_modules/zeppelin-tabledata")),
          new File(zconf.getRelativeDir("lib/node_modules/zeppelin-vis")));
    } else {
      heliumVisualizationFactory = new HeliumVisualizationFactory(
          zconf,
          new File(zconf.getRelativeDir(ConfVars.ZEPPELIN_DEP_LOCALREPO)),
          //new File(zconf.getRelativeDir("zeppelin-web/src/app/tabledata")),
          //new File(zconf.getRelativeDir("zeppelin-web/src/app/visualization")));
          new File(zconf.getRelativeDir("smart-zeppelin/zeppelin-web/src/app/tabledata")),
          new File(zconf.getRelativeDir("smart-zeppelin/zeppelin-web/src/app/visualization")));
    }

    this.helium = new Helium(
        zconf.getHeliumConfPath(),
        zconf.getHeliumDefaultLocalRegistryPath(),
        heliumVisualizationFactory,
        heliumApplicationFactory);

    // create visualization bundle
    try {
      heliumVisualizationFactory.bundle(helium.getVisualizationPackagesToBundle());
    } catch (Exception e) {
      LOG.error(e.getMessage(), e);
    }

    this.schedulerFactory = new SchedulerFactory();
    this.interpreterSettingManager = new InterpreterSettingManager(zconf, depResolver,
        new InterpreterOption(true));
    this.noteSearchService = new LuceneSearch();
    this.notebookAuthorization = NotebookAuthorization.init(zconf);
    this.credentials = new Credentials(zconf.credentialsPersist(), zconf.getCredentialsPath());
  }

  // 判断Web UI是否启用
  private boolean isZeppelinWebEnabled() {
    return conf.getBoolean(SmartConfKeys.SMART_ENABLE_ZEPPELIN_WEB,
        SmartConfKeys.SMART_ENABLE_ZEPPELIN_WEB_DEFAULT);
  }

  // SmartZeppelinServer 入口
  public static void main(String[] args) throws Exception {
    // 实例化一个server对象
    SmartZeppelinServer server = new SmartZeppelinServer(new SmartConf(), null);

    // 启动server
    server.start();

  }

  // 开启ssm web server
  public void start() throws Exception {
      // 根据配置对象实例化嵌入式jetty服务
    jettyWebServer = setupJettyServer(zconf);

    // 实例化jetty context存储容器
    ContextHandlerCollection contexts = new ContextHandlerCollection();
    // 为jetty配置handler，handler即为以上contexts容器中的所有context
    jettyWebServer.setHandler(contexts);

    // 创建WebAppContext并配置，并将此context加入到contexts集合中。——Web UI相关
    final WebAppContext webApp = setupWebAppContext(contexts);

    // 初始化Zeppelin配置，主要是Helium的配置。查看Zeppelin的Interpreter文档理解比较好。
    init();

    // 设置RestApi相关，并把RestApi处理的Servlet映射到WebAppContext。这样contexts就是全局的Context管理器。
    // 219行主要用于给WebAppContext绑定WebUi资源，225行用于给WebAppContext设置Servlet处理映射。
    setupRestApiContextHandler(webApp);

    LOG.info("Starting zeppelin server");
    try {
        // 开启已经配置好的Jetty服务。
      jettyWebServer.start(); //Instantiates ZeppelinServer
    } catch (Exception e) {
      LOG.error("Error while running jettyServer", e);
      //System.exit(-1);
    }
    LOG.info("Done, zeppelin server started");

    // 在jvm正常关闭之前调用。用于做点收尾工作。
    Runtime.getRuntime().addShutdownHook(new Thread(){
      @Override public void run() {
        LOG.info("Shutting down Zeppelin Server ... ");
        try {
          if (jettyWebServer != null) {
            jettyWebServer.stop();
          }
          if (notebook != null) {
            notebook.getInterpreterSettingManager().shutdown();
            notebook.close();
          }
          Thread.sleep(1000);
        } catch (Exception e) {
          LOG.error("Error while stopping servlet container", e);
        }
        LOG.info("Bye");
      }
    });
  }

  public void stop() {
    LOG.info("Shutting down Zeppelin Server ... ");
    try {
      if (jettyWebServer != null) {
        jettyWebServer.stop();
      }
      if (notebook != null) {
        notebook.getInterpreterSettingManager().shutdown();
        notebook.close();
      }
      Thread.sleep(1000);
    } catch (Exception e) {
      LOG.error("Error while stopping servlet container", e);
    }
    LOG.info("Bye");
  }

  // 实例化一个JettyServer，并且根据配置中的内容，对JettyServer做出配置修改。
  private static Server setupJettyServer(ZeppelinConfiguration zconf) {

    final Server server = new Server();
    ServerConnector connector;

    if (zconf.useSsl()) {
      LOG.debug("Enabling SSL for Zeppelin Server on port " + zconf.getServerSslPort());
      HttpConfiguration httpConfig = new HttpConfiguration();
      httpConfig.setSecureScheme("https");
      httpConfig.setSecurePort(zconf.getServerSslPort());
      httpConfig.setOutputBufferSize(32768);
      httpConfig.setRequestHeaderSize(8192);
      httpConfig.setResponseHeaderSize(8192);
      httpConfig.setSendServerVersion(true);

      HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
      SecureRequestCustomizer src = new SecureRequestCustomizer();
      // Only with Jetty 9.3.x
      // src.setStsMaxAge(2000);
      // src.setStsIncludeSubDomains(true);
      httpsConfig.addCustomizer(src);

      connector = new ServerConnector(
              server,
              new SslConnectionFactory(getSslContextFactory(zconf),
                  HttpVersion.HTTP_1_1.asString()),
              new HttpConnectionFactory(httpsConfig));
    } else {
      connector = new ServerConnector(server);
    }

    // Set some timeout options to make debugging easier.
    int timeout = 1000 * 30;
    connector.setIdleTimeout(timeout);
    connector.setSoLingerTime(-1);

    String webUrl = "";
    connector.setHost(zconf.getServerAddress());
    if (zconf.useSsl()) {
      connector.setPort(zconf.getServerSslPort());
      webUrl = "https://" + zconf.getServerAddress() + ":" + zconf.getServerSslPort();
    } else {
      connector.setPort(zconf.getServerPort());
      webUrl = "http://" + zconf.getServerAddress() + ":" + zconf.getServerPort();
    }

    LOG.info("Web address:" + webUrl);
    server.addConnector(connector);

    return server;
  }

  private static SslContextFactory getSslContextFactory(ZeppelinConfiguration zconf) {
    SslContextFactory sslContextFactory = new SslContextFactory();

    // Set keystore
    sslContextFactory.setKeyStorePath(zconf.getKeyStorePath());
    sslContextFactory.setKeyStoreType(zconf.getKeyStoreType());
    sslContextFactory.setKeyStorePassword(zconf.getKeyStorePassword());
    sslContextFactory.setKeyManagerPassword(zconf.getKeyManagerPassword());

    if (zconf.useClientAuth()) {
      sslContextFactory.setNeedClientAuth(zconf.useClientAuth());

      // Set truststore
      sslContextFactory.setTrustStorePath(zconf.getTrustStorePath());
      sslContextFactory.setTrustStoreType(zconf.getTrustStoreType());
      sslContextFactory.setTrustStorePassword(zconf.getTrustStorePassword());
    }

    return sslContextFactory;
  }

  // 配置Restful应用
  class SmartRestApp extends Application {
      // 返回所有privider和资源类类型，用于注册。
    @Override
    public Set<Class<?>> getClasses() {
      Set<Class<?>> classes = new HashSet<>();
      return classes;
    }

    // 返回所有provider和资源类的单例对象，用于注册。
    @Override
    public Set<Object> getSingletons() {
      Set<Object> singletons = new HashSet<>();

      // 下面都是集合添加的常规操作，按下不表。
      SystemRestApi systemApi = new SystemRestApi(engine);
      singletons.add(systemApi);

      ConfRestApi confApi = new ConfRestApi(engine);
      singletons.add(confApi);

      ActionRestApi actionApi = new ActionRestApi(engine);
      singletons.add(actionApi);

      ClusterRestApi clusterApi = new ClusterRestApi(engine);
      singletons.add(clusterApi);

      CmdletRestApi cmdletApi = new CmdletRestApi(engine);
      singletons.add(cmdletApi);

      RuleRestApi ruleApi = new RuleRestApi(engine);
      singletons.add(ruleApi);

      NoteBookRestApi notebookApi = new NoteBookRestApi(engine);
      singletons.add(notebookApi);

      return singletons;
    }
  }

  // Zeppelin的RestApp，提供一些登录验证服务
  class ZeppelinRestApp extends Application {
    @Override
    public Set<Class<?>> getClasses() {
      Set<Class<?>> classes = new HashSet<>();
      return classes;
    }

    @Override
    public Set<Object> getSingletons() {
      Set<Object> singletons = new HashSet<>();

      /** Rest-api root endpoint */
      ZeppelinRestApi root = new ZeppelinRestApi();
      singletons.add(root);

      HeliumRestApi heliumApi = new HeliumRestApi(helium, notebook);
      singletons.add(heliumApi);

      CredentialRestApi credentialApi = new CredentialRestApi(credentials);
      singletons.add(credentialApi);

      SecurityRestApi securityApi = new SecurityRestApi();
      singletons.add(securityApi);

      LoginRestApi loginRestApi = new LoginRestApi();
      singletons.add(loginRestApi);

      return singletons;
    }
  }

  private void setupRestApiContextHandler(WebAppContext webApp) throws Exception {
    // 为WebAppContext设置SessionHandler。
      /*
      * 注意：Jetty中的Context处理流程为ServletContextHandler—>SessionHandler—>SecurityHandler—>ServletHandler的
      * Handler链。所以这里的SessionHandler会在ServletContextHandler（Web UI）与SecurityHandler之间执行。
      * */
    webApp.setSessionHandler(new SessionHandler());

    // 注册Restful api。
    ResourceConfig smartConfig = new ApplicationAdapter(new SmartRestApp());
    // 将Jersey资源类通过ServletContainer转化为Servlet，用于jetty加载。
    ServletHolder smartServletHolder = new ServletHolder(new ServletContainer(smartConfig));
    // 将此Servlet与要处理的请求路径映射。
    webApp.addServlet(smartServletHolder, SMART_PATH_SPEC);

    // 以下三行同上
    ResourceConfig zeppelinConfig = new ApplicationAdapter(new ZeppelinRestApp());
    ServletHolder zeppelinServletHolder = new ServletHolder(new ServletContainer(zeppelinConfig));
    webApp.addServlet(zeppelinServletHolder, ZEPPELIN_PATH_SPEC);

    // 设置Shiro过滤器，用于登录验证。默认未启用，用户名密码写在ZeppelinRestApp的LoginRestApi中。
    String shiroIniPath = zconf.getShiroPath();
    if (!StringUtils.isBlank(shiroIniPath)) {
      webApp.setInitParameter("shiroConfigLocations",
          new File(shiroIniPath).toURI().toString());
      SecurityUtils.initSecurityManager(shiroIniPath);
      webApp.addFilter(ShiroFilter.class, "/api/*", EnumSet.allOf(DispatcherType.class));
      webApp.addEventListener(new EnvironmentLoaderListener());
    }
  }

  // 设置WEB UI的处理context
  private WebAppContext setupWebAppContext(ContextHandlerCollection contexts) {

      // 实例化WebAppContext
    WebAppContext webApp = new WebAppContext();
    // 设置WebAppContext的服务路径为/
    webApp.setContextPath(zconf.getServerContextPath());
    // 如果配置中不启用web ui
    if (!isZeppelinWebEnabled()) {
        // 不设置web ui的资源目录
      webApp.setResourceBase("");
      // 将此空的WebAppContext加入到contexts集合中
      contexts.addHandler(webApp);
      // 退出函数
      return webApp;
    }

    // 如果配置中启用web ui
      // 配置war资源地址
    File warPath = new File(zconf.getString(ConfVars.ZEPPELIN_WAR));
    //File warPath = new File("../dist/zeppelin-web-0.7.2.war");
      // 如果该war资源是目录
    if (warPath.isDirectory()) {
        // 将此war目录设置为web context的资源目录
      webApp.setResourceBase(warPath.getPath());
      // 设置资源加载优先级
      webApp.setParentLoaderPriority(true);
    } else {
        // 如果该war资源是war包的形式，则为WebAppContext设置该war包作为服务资源
      webApp.setWar(warPath.getAbsolutePath());
      // 从配置中得到war包临时目录
      File warTempDirectory = new File(zconf.getRelativeDir(ConfVars.ZEPPELIN_WAR_TEMPDIR));
      // 创建该目录
      warTempDirectory.mkdir();
      LOG.info("ZeppelinServer Webapp path: {}", warTempDirectory.getPath());
      // war包中的资源会被释放到该目录
      webApp.setTempDirectory(warTempDirectory);
    }
    // 指定WebAppContext服务的Servlet映射，默认“/”路径使用默认Servlet处理。
    // DefaultServlet用于将用户请求的相对路径修改为服务器的绝对路径进行资源处理。
    webApp.addServlet(new ServletHolder(new DefaultServlet()), "/*");
      // 将WebAppContext加入到contexts集合中
    contexts.addHandler(webApp);
    // 增加过滤器，并且配置过滤器过滤地址
    webApp.addFilter(new FilterHolder(CorsFilter.class), "/*",
        EnumSet.allOf(DispatcherType.class));

    return webApp;
  }

  /**
   * Check if it is source build or binary package
   * @return
   */
  private static boolean isBinaryPackage(ZeppelinConfiguration conf) {
    return !new File(conf.getRelativeDir("smart-zeppelin/zeppelin-web")).isDirectory();
  }
}
