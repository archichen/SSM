/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.server.engine;

import org.smartdata.SmartContext;
import org.smartdata.conf.SmartConf;
import org.smartdata.metaservice.MetaService;
import org.smartdata.metastore.MetaStore;

// ServerContext集成了SmartContext，拥有父类获取SmartConf的能力，并且拓展了父类功能。
// 增加了可以获得MetaStore和ServerMode（枚举型，支持HDFS和ALLUXIO）的功能。
public class ServerContext extends SmartContext {

  private MetaStore metaStore;

  private ServiceMode serviceMode;

  public ServerContext(MetaStore metaStore) {
    this.metaStore = metaStore;
  }

  public ServerContext(SmartConf conf, MetaStore metaStore) {
    // 重新配置一下SmartConf
    super(conf);
    this.metaStore = metaStore;
  }

  public MetaStore getMetaStore() {
    return metaStore;
  }

  public MetaService getMetaService() {
    return metaStore;
  }

  public ServiceMode getServiceMode() {
    return serviceMode;
  }

  public void setServiceMode(ServiceMode serviceMode) {
    this.serviceMode = serviceMode;
  }
}
