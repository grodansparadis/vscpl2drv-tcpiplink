// vscptcpip.cpp: implementation of the CTcpipLink class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP Project (http://www.vscp.org)
//
// Copyright (C) 2000-2020 Ake Hedman,
// Grodans Paradis AB, <akhe@grodansparadis.com>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#include "tcpiplink.h"

#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <ctype.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <expat.h>

#include <hlo.h>
#include <remotevariablecodes.h>
#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscpdatetime.h>
#include <vscphelper.h>
#include <vscpremotetcpif.h>

#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <string>

// Buffer for XML parser
#define XML_BUFF_SIZE 50000

#include <json.hpp> // Needs C++11  -std=c++11
#include <mustache.hpp>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

// https://github.com/nlohmann/json
using json = nlohmann::json;
using namespace kainjow::mustache;

// Forward declaration
void *
workerThreadReceive(void *pData);
void *
workerThreadSend(void *pData);

//////////////////////////////////////////////////////////////////////
// CTcpipLink
//

CTcpipLink::CTcpipLink()
{
  m_bDebug       = false;
  m_bWriteEnable = false;
  m_bQuit        = false;

  vscp_clearVSCPFilter(&m_filterIn);  // Accept all events
  vscp_clearVSCPFilter(&m_filterOut); // Send all events
  m_responseTimeout = TCPIP_DEFAULT_INNER_RESPONSE_TIMEOUT;

  sem_init(&m_semSendQueue, 0, 0);
  sem_init(&m_semReceiveQueue, 0, 0);

  pthread_mutex_init(&m_mutexSendQueue, NULL);
  pthread_mutex_init(&m_mutexReceiveQueue, NULL);

  // Init pool
  spdlog::init_thread_pool(8192, 1);

  // Flush log every five seconds
  spdlog::flush_every(std::chrono::seconds(5));

  auto console = spdlog::stdout_color_mt("console");
  // Start out with level=info. Config may change this
  console->set_level(spdlog::level::debug);
  console->set_pattern("[vscpl2drv-websrv] [%^%l%$] %v");
  spdlog::set_default_logger(console);

  console->debug("Starting the vscpl2drv-websrv...");

  m_bConsoleLogEnable = true;
  m_consoleLogLevel   = spdlog::level::info;
  m_consoleLogPattern = "[vscpl2drv-tcpiplink %c] [%^%l%$] %v";

  m_bFileLogEnable   = true;
  m_fileLogLevel     = spdlog::level::info;
  m_fileLogPattern   = "[vscpl2drv-tcpiplink %c] [%^%l%$] %v";
  m_path_to_log_file = "/var/log/vscp/vscpl2drv-tcpiplink.log";
  m_max_log_size     = 5242880;
  m_max_log_files    = 7;

  m_web_ssl_certificate          = "/srv/vscp/certs/tcpip_server.pem";
  m_web_ssl_certificate_chain    = "";
  m_web_ssl_verify_peer          = false;
  m_web_ssl_ca_path              = "";
  m_web_ssl_ca_file              = "";
  m_web_ssl_verify_depth         = 9;
  m_web_ssl_default_verify_paths = true;
  m_web_ssl_cipher_list          = "DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256";
  m_web_ssl_protocol_version     = 4;
  m_web_ssl_short_trust          = false;
  m_web_ssl_cache_timeout        = -1;
}

//////////////////////////////////////////////////////////////////////
// ~CTcpipLink
//

CTcpipLink::~CTcpipLink()
{
  close();

  sem_destroy(&m_semSendQueue);
  sem_destroy(&m_semReceiveQueue);

  pthread_mutex_destroy(&m_mutexSendQueue);
  pthread_mutex_destroy(&m_mutexReceiveQueue);

  // Shutdown logger in a nice way
  spdlog::drop_all();
  spdlog::shutdown();
}

// ----------------------------------------------------------------------------

/*
    XML configuration
    -----------------

    <setup host="localhost"
              port="9598"
              user="admin"
              password="secret"
              rxfilter=""
              rxmask=""
              txfilter=""
              txmask=""
              responsetimeout="2000" />
*/

// ----------------------------------------------------------------------------

// int depth_setup_parser = 0;

// void
// startSetupParser(void *data, const char *name, const char **attr)
// {
//   CTcpipLink *pObj = (CTcpipLink *) data;
//   if (NULL == pObj) {
//     return;
//   }

//   if ((0 == strcmp(name, "config")) && (0 == depth_setup_parser)) {

//     for (int i = 0; attr[i]; i += 2) {

//       std::string attribute = attr[i + 1];
//       vscp_trim(attribute);

//       if (0 == strcasecmp(attr[i], "debug")) {
//         if (!attribute.empty()) {
//           if ("true" == attribute) {
//             pObj->m_bDebug = true;
//           }
//           else {
//             pObj->m_bDebug = false;
//           }
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "write")) {
//         if (!attribute.empty()) {
//           if ("true" == attribute) {
//             pObj->m_bAllowWrite = true;
//           }
//           else {
//             pObj->m_bAllowWrite = false;
//           }
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "remote-host")) {
//         if (!attribute.empty()) {
//           pObj->m_hostRemote = attribute;
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "remote-port")) {
//         if (!attribute.empty()) {
//           pObj->m_portRemote = vscp_readStringValue(attribute);
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "remote-user")) {
//         if (!attribute.empty()) {
//           pObj->m_usernameRemote = attribute;
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "remote-password")) {
//         if (!attribute.empty()) {
//           pObj->m_passwordRemote = attribute;
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "rxfilter")) {
//         if (!attribute.empty()) {
//           if (!vscp_readFilterFromString(&pObj->m_filterIn, attribute)) {
//             syslog(LOG_ERR,
//                    "Unable to read event receive filter.");
//           }
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "rxmask")) {
//         if (!attribute.empty()) {
//           if (!vscp_readMaskFromString(&pObj->m_filterIn, attribute)) {
//             syslog(LOG_ERR,
//                    "Unable to read event receive mask.");
//           }
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "txfilter")) {
//         if (!attribute.empty()) {
//           if (!vscp_readFilterFromString(&pObj->m_filterOut, attribute)) {
//             syslog(LOG_ERR,
//                    "Unable to read event transmit filter.");
//           }
//         }
//       }
//       else if (0 == strcasecmp(attr[i], "txmask")) {
//         if (!attribute.empty()) {
//           if (!vscp_readMaskFromString(&pObj->m_filterOut, attribute)) {
//             syslog(LOG_ERR,
//                    "Unable to read event transmit mask.");
//           }
//         }
//       }
//       else if (0 == strcmp(attr[i], "response-timeout")) {
//         if (!attribute.empty()) {
//           pObj->m_responseTimeout = vscp_readStringValue(attribute);
//         }
//       }
//     }
//   }

//   depth_setup_parser++;
// }

// void
// endSetupParser(void *data, const char *name)
// {
//   depth_setup_parser--;
// }

// ----------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////
// open
//
//

bool
CTcpipLink::open(std::string &path, const cguid &guid)
{
  // Set GUID
  m_guid = guid;

  // Save path to config file
  m_path = path;

  // Read configuration file
  if (!doLoadConfig()) {
    spdlog::error("Failed to load configuration file {}", path);
  }

  // start the workerthread
  if (pthread_create(&m_pthreadSend, NULL, workerThreadSend, this)) {
    spdlog::critical("Failed to load configuration file [{}]", path);
    return false;
  }

  if (pthread_create(&m_pthreadReceive, NULL, workerThreadReceive, this)) {
    spdlog::error("Unable to start receive worker thread.");
    return false;
  }

  return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
CTcpipLink::close(void)
{
  // Do nothing if already terminated
  if (m_bQuit)
    return;

  m_bQuit = true; // terminate the thread
  sleep(1);       // Give the thread some time to terminate
}

// ----------------------------------------------------------------------------

int depth_hlo_parser = 0;

void
startHLOParser(void *data, const char *name, const char **attr)
{
  CHLO *pObj = (CHLO *) data;
  if (NULL == pObj) {
    return;
  }
  /*
      if ((0 == strcmp(name, "vscp-cmd")) && (0 == depth_setup_parser)) {

          for (int i = 0; attr[i]; i += 2) {

              std::string attribute = attr[i + 1];
              vscp_trim(attribute);

              if (0 == strcasecmp(attr[i], "op")) {
                  if (!attribute.empty()) {
                      pObj->m_op = vscp_readStringValue(attribute);
                      vscp_makeUpper(attribute);
                      if (attribute == "VSCP-NOOP") {
                          pObj->m_op = HLO_OP_NOOP;
                      } else if (attribute == "VSCP-READVAR") {
                          pObj->m_op = HLO_OP_READ_VAR;
                      } else if (attribute == "VSCP-WRITEVAR") {
                          pObj->m_op = HLO_OP_WRITE_VAR;
                      } else if (attribute == "VSCP-LOAD") {
                          pObj->m_op = HLO_OP_LOAD;
                      } else if (attribute == "VSCP-SAVE") {
                          pObj->m_op = HLO_OP_SAVE;
                      } else if (attribute == "CALCULATE") {
                          pObj->m_op = HLO_OP_SAVE;
                      } else {
                          pObj->m_op = HLO_OP_UNKNOWN;
                      }
                  }
              } else if (0 == strcasecmp(attr[i], "name")) {
                  if (!attribute.empty()) {
                      vscp_makeUpper(attribute);
                      pObj->m_name = attribute;
                  }
              } else if (0 == strcasecmp(attr[i], "type")) {
                  if (!attribute.empty()) {
                      pObj->m_varType = vscp_readStringValue(attribute);
                  }
              } else if (0 == strcasecmp(attr[i], "value")) {
                  if (!attribute.empty()) {
                      if (vscp_base64_std_decode(attribute)) {
                          pObj->m_value = attribute;
                      }
                  }
              } else if (0 == strcasecmp(attr[i], "full")) {
                  if (!attribute.empty()) {
                      vscp_makeUpper(attribute);
                      if ("TRUE" == attribute) {
                          pObj->m_bFull = true;
                      } else {
                          pObj->m_bFull = false;
                      }
                  }
              }
          }
      }

      depth_hlo_parser++;
  */
}

void
endHLOParser(void *data, const char *name)
{
  depth_hlo_parser--;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// parseHLO
//

bool
CTcpipLink::parseHLO(uint16_t size, uint8_t *inbuf, CHLO *phlo)
{
  // Check pointers
  if (NULL == inbuf) {
    spdlog::error("HLO parser: HLO in-buffer pointer is NULL.");
    return false;
  }

  if (NULL == phlo) {
    spdlog::error("HLO parser: HLO obj pointer is NULL.");
    return false;
  }

  if (!size) {
    spdlog::error("HLO parser: HLO buffer size is zero.");
    return false;
  }

  XML_Parser xmlParser = XML_ParserCreate("UTF-8");
  XML_SetUserData(xmlParser, this);
  XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

  void *buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

  // Copy in the HLO object
  memcpy(buf, inbuf, size);

  if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
    spdlog::error("Failed parse XML setup.");
    XML_ParserFree(xmlParser);
    return false;
  }

  XML_ParserFree(xmlParser);

  return true;
}

// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------

/////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

bool
CTcpipLink::readEncryptionKey(const std::string &path)
{
  bool rv = false; // Be negative today

  try {
    std::string vscpkey;
    std::ifstream in(path, std::ifstream::in);
    std::stringstream strStream;
    strStream << in.rdbuf();
    vscpkey = strStream.str();
    vscp_trim(vscpkey);
    spdlog::get("logger")->debug("vscp.key [{}]", vscpkey.c_str());
    rv = vscp_hexStr2ByteArray(m_vscp_key, 32, vscpkey.c_str());
  }
  catch (...) {
    spdlog::get("logger")->error("Failed to read encryption key file [{}]", m_path.c_str());
  }

  return rv;
}

///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

// bool
// CTcpipLink::doLoadConfig(void)
// {
//   FILE *fp;

//   fp = fopen(m_path.c_str(), "r");
//   if (NULL == fp) {
//     spdlog::error("Failed to open configuration file [{}]", m_path);
//     return false;
//   }

//   XML_Parser xmlParser = XML_ParserCreate("UTF-8");
//   XML_SetUserData(xmlParser, this);
//   XML_SetElementHandler(xmlParser, startSetupParser, endSetupParser);

//   void *buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

//   size_t file_size = 0;
//   file_size        = fread(buf, sizeof(char), XML_BUFF_SIZE, fp);
//   fclose(fp);

//   if (!XML_ParseBuffer(xmlParser, file_size, file_size == 0)) {
//     spdlog::error("Failed parse XML setup.");
//     XML_ParserFree(xmlParser);
//     return false;
//   }

//   XML_ParserFree(xmlParser);

//   return true;
// }

bool
CTcpipLink::doLoadConfig(void)
{
  try {
    std::ifstream in(m_path, std::ifstream::in);
    in >> m_j_config;
  }
  catch (json::parse_error &e) {
    spdlog::critical("Failed to load/parse JSON configuration. message: {}, id: {}, pos: {} ", e.what(), e.id, e.byte);
    return false;
  }
  catch (...) {
    spdlog::critical("Unknown exception when loading JSON configuration.");
    return false;
  }

  spdlog::debug("Reading configuration from [{}]", m_path);

  // Logging
  if (m_j_config.contains("logging") && m_j_config["logging"].is_object()) {

    json j = m_j_config["logging"];

    // * * *  CONSOLE  * * *

    // Logging: console-log-enable
    if (j.contains("console-enable")) {
      try {
        m_bConsoleLogEnable = j["console-enable"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'console-enable' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-enable' due to unknown error.");
      }
    }
    else {
      spdlog::debug("Failed to read LOGGING 'console-enable' Defaults will be used.");
    }

    // Logging: console-log-level
    if (j.contains("console-level")) {
      std::string str;
      try {
        str = j["console-level"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'console-level' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-level' due to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_consoleLogLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_consoleLogLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_consoleLogLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_consoleLogLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_consoleLogLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_consoleLogLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_consoleLogLevel = spdlog::level::trace;
      }
      else {
        spdlog::error("Failed to read LOGGING 'console-level' has invalid "
                      "value [{}]. Default value used.",
                      str);
      }
    }
    else {
      spdlog::error("Failed to read LOGGING 'console-level' Defaults will be used.");
    }

    // Logging: console-log-pattern
    if (j.contains("console-pattern")) {
      try {
        m_consoleLogPattern = j["console-pattern"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'console-pattern' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'console-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug("Failed to read LOGGING 'console-pattern' Defaults will be used.");
    }

    // * * *  FILE  * * *

    // Logging: file-log-enable
    if (j.contains("file-enable")) {
      try {
        m_bFileLogEnable = j["file-enable"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-enable' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-enable' due to unknown error.");
      }
    }
    else {
      spdlog::debug("Failed to read LOGGING 'file-enable' Defaults will be used.");
    }

    // Logging: file-log-level
    if (j.contains("file-log-level")) {
      std::string str;
      try {
        str = j["file-log-level"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-level' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-level' due to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_fileLogLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_fileLogLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_fileLogLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_fileLogLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_fileLogLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_fileLogLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_fileLogLevel = spdlog::level::trace;
      }
      else {
        spdlog::error("Failed to read LOGGING 'file-log-level' has invalid value "
                      "[{}]. Default value used.",
                      str);
      }
    }
    else {
      spdlog::error("Failed to read LOGGING 'file-log-level' Defaults will be used.");
    }

    // Logging: file-log-pattern
    if (j.contains("file-log-pattern")) {
      try {
        m_fileLogPattern = j["file-log-pattern"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-pattern' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug("Failed to read LOGGING 'file-log-pattern' Defaults will be used.");
    }

    // Logging: file-log-path
    if (j.contains("file-log-path")) {
      try {
        m_path_to_log_file = j["file-log-path"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-path' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-path' due to unknown error.");
      }
    }
    else {
      spdlog::error(" Failed to read LOGGING 'file-log-path' Defaults will be used.");
    }

    // Logging: file-log-max-size
    if (j.contains("file-log-max-size")) {
      try {
        m_max_log_size = j["file-log-max-size"].get<uint32_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-max-size' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-max-size' due to unknown error.");
      }
    }
    else {
      spdlog::error("Failed to read LOGGING 'file-log-max-size' Defaults will be used.");
    }

    // Logging: file-log-max-files
    if (j.contains("file-log-max-files")) {
      try {
        m_max_log_files = j["file-log-max-files"].get<uint16_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-log-max-files' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'file-log-max-files' due to unknown error.");
      }
    }
    else {
      spdlog::error("Failed to read LOGGING 'file-log-max-files' Defaults will be used.");
    }

  } // Logging
  else {
    spdlog::error("No logging has been setup.");
  }

  ///////////////////////////////////////////////////////////////////////////
  //                          Setup logger
  ///////////////////////////////////////////////////////////////////////////

  // Console log
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  if (m_bConsoleLogEnable) {
    console_sink->set_level(m_consoleLogLevel);
    console_sink->set_pattern(m_consoleLogPattern);
  }
  else {
    // If disabled set to off
    console_sink->set_level(spdlog::level::off);
  }

  // auto rotating =
  // std::make_shared<spdlog::sinks::rotating_file_sink_mt>("log_filename",
  // 1024*1024, 5, false);
  auto rotating_file_sink =
    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(m_path_to_log_file.c_str(), m_max_log_size, m_max_log_files);

  if (m_bFileLogEnable) {
    rotating_file_sink->set_level(m_fileLogLevel);
    rotating_file_sink->set_pattern(m_fileLogPattern);
  }
  else {
    // If disabled set to off
    rotating_file_sink->set_level(spdlog::level::off);
  }

  std::vector<spdlog::sink_ptr> sinks{ console_sink, rotating_file_sink };
  auto logger = std::make_shared<spdlog::async_logger>("logger",
                                                       sinks.begin(),
                                                       sinks.end(),
                                                       spdlog::thread_pool(),
                                                       spdlog::async_overflow_policy::block);
  // The separate sub loggers will handle trace levels
  logger->set_level(spdlog::level::trace);
  spdlog::register_logger(logger);

  // ------------------------------------------------------------------------

  // write
  if (m_j_config.contains("write")) {
    try {
      m_bWriteEnable = m_j_config["write"].get<bool>();
      spdlog::debug("bWriteEnable set to {}", m_bWriteEnable);
    }
    catch (const std::exception &ex) {
      spdlog::error("Failed to read 'write' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("Failed to read 'write' due to unknown error.");
    }
  }
  else {
    spdlog::error("Failed to read 'write' item from configuration file. "
                  "Defaults will be used.");
  }

  // VSCP key file
  if (m_j_config.contains("key-file") && m_j_config["key-file"].is_string()) {
    if (!readEncryptionKey(m_j_config["key-file"].get<std::string>())) {
      spdlog::warn("Failed to read VSCP key from file [{}]. Default key will "
                   "be used. Dangerous!",
                   m_j_config["key-file"].get<std::string>());
    }
    else {
      spdlog::debug("key-file {} read successfully", m_j_config["key-file"].get<std::string>());
    }
  }
  else {
    spdlog::warn("VSCP key file is not defined. Default key will be used. Dangerous!");
  }

  // Filter
  if (m_j_config.contains("filter") && m_j_config["filter"].is_object()) {

    json j = m_j_config["filter"];

    // IN filter
    if (j.contains("in-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'in-filter' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'in-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read LOGGING 'in-filter' Defaults will be used.");
    }

    // IN mask
    if (j.contains("in-mask")) {
      try {
        std::string str = j["in-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'in-mask' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'in-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'in-mask' Defaults will be used.");
    }

    // OUT filter
    if (j.contains("out-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'out-filter' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'out-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'out-filter' Defaults will be used.");
    }

    // OUT mask
    if (j.contains("out-mask")) {
      try {
        std::string str = j["out-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'out-mask' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'out-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'out-mask' Defaults will be used.");
    }
  }

  ///////////////////////////////////////////////////////////////////////
  //                            Remote host
  ///////////////////////////////////////////////////////////////////////

  // Remote
  if (m_j_config.contains("remote") && m_j_config["remote"].is_object()) {

    json j = m_j_config["remote"];

    if (j.contains("host") && j["host"].is_string()) {
      try {
        m_hostRemote = j["host"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'host' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'host' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'host' Defaults will be used.");
    }

    if (j.contains("port") && j["port"].is_number()) {
      try {
        m_portRemote = j["port"].get<short>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'port' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'port' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'port' Defaults will be used.");
    }

    if (j.contains("user") && j["user"].is_string()) {
      try {
        m_usernameRemote = j["user"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'user' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'user' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'user' Defaults will be used.");
    }

    // Remote password
    if (j.contains("password") && j["password"].is_string()) {
      try {
        m_passwordRemote = j["password"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'password' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'password' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'password' Defaults will be used.");
    }

    // Response timeout
    if (j.contains("response-timeout") && j["response-timeout"].is_number_unsigned()) {
      try {
        m_responseTimeout = j["response-timeout"].get<uint32_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'response-timeout' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'response-timeout' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'response-timeout' Defaults will be used.");
    }

  }

  ///////////////////////////////////////////////////////////////////////
  //                                TLS
  ///////////////////////////////////////////////////////////////////////

  // TLS / SSL
  if (m_j_config.contains("tls") && m_j_config["tls"].is_object()) {

    json j = m_j_config["tls"];

    // Certificate
    // Path to the SSL certificate file. This option is only required when at
    // least one of the listening\_ports is SSL. The file must be in PEM
    // format, and it must have both, private key and certificate, see for
    // example ssl_cert.pem A description how to create a certificate can be
    // found in doc/OpenSSL.md

    if (j.contains("certificate")) {
      try {
        m_web_ssl_certificate = j["certificate"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'certificate' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'certificate' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'certificate' Defaults will be used.");
    }

    // certificate chain
    // Path to an SSL certificate chain file. As a default, the
    // ssl_certificate file is used.

    if (j.contains("certificate-chain")) {
      try {
        m_web_ssl_certificate_chain = j["certificate-chain"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'certificate-chain' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'certificate-chain' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'certificate-chain' Defaults will be used.");
    }

    // verify peer: false
    // Enable client's certificate verification by the server.

    if (j.contains("verify-peer")) {
      try {
        m_web_ssl_verify_peer = j["verify-peer"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'verify-peer' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'verify-peer' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'verify-peer' Defaults will be used.");
    }

    // CA Path
    // Name of a directory containing trusted CA certificates. Each file in
    // the directory must contain only a single CA certificate. The files must
    // be named by the subject name’s hash and an extension of “.0”. If there
    // is more than one certificate with the same subject name they should
    // have extensions ".0", ".1", ".2" and so on respectively.

    if (j.contains("ca-path")) {
      try {
        m_web_ssl_ca_path = j["ca-path"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'ca-path' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'ca-path' due to unknown error.");
      }
    }
    else {
      spdlog::debug("  Failed to read 'ca-path' Defaults will be used.");
    }

    // CA File
    // Path to a .pem file containing trusted certificates. The file may
    // contain more than one certificate.

    if (j.contains("ca-file")) {
      try {
        m_web_ssl_ca_file = j["ca-file"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'ca-file' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'ca-file' due to unknown error.");
      }
    }
    else {
      spdlog::debug("  Failed to read 'ca-file' Defaults will be used.");
    }

    // Verify depth: 9
    // Sets maximum depth of certificate chain. If client's certificate chain
    // is longer than the depth set here connection is refused.

    if (j.contains("verify-depth")) {
      try {
        m_web_ssl_verify_depth = j["verify-depth"].get<uint16_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error(" Failed to read 'verify-depth' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error(" Failed to read 'verify-depth' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'verify-depth' Defaults will be used.");
    }

    // Default verify paths : true
    // Loads default trusted certificates locations set at openssl compile
    // time.

    if (j.contains("default-verify-paths")) {
      try {
        m_web_ssl_default_verify_paths = j["default-verify-paths"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'default-verify-paths' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'default-verify-paths' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'default-verify-paths' Defaults will be used.");
    }

    // Chiper list
    // List of ciphers to present to the client. Entries should be separated
    // by colons, commas or spaces.
    //
    // ALL           All available ciphers
    // ALL:!eNULL    All ciphers excluding NULL ciphers
    // AES128:!MD5   AES 128 with digests other than MD5
    // See this entry in OpenSSL documentation for full list of options and
    // additional examples.

    if (j.contains("cipher-list")) {
      try {
        m_web_ssl_cipher_list = j["cipher-list"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'cipher-list' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'cipher-list' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'cipher-list' Defaults will be used.");
    }

    // Protocol version
    // Sets the minimal accepted version of SSL/TLS protocol according to the
    // table:
    //
    // Protocols	                            Value
    // SSL2+SSL3+TLS1.0+TLS1.1+TLS1.2+TLS1.3	0
    // SSL3+TLS1.0+TLS1.1+TLS1.2+TLS1.3	        1
    // TLS1.0+TLS1.1+TLS1.2+TLS1.3	            2
    // TLS1.1+TLS1.2+TLS1.3	                    3
    // TLS1.2+TLS1.3	                        4
    // TLS1.3	                                5
    //
    // TLS version 1.3 is only available if you are using an up-to-date TLS
    // libary. The default setting has been changed from 0 to 4 in
    // CivetWeb 1.14.

    if (j.contains("protocol-version")) {
      try {
        m_web_ssl_protocol_version = j["protocol-version"].get<uint16_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'protocol-version' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'protocol-version' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'protocol-version' Defaults will be used.");
    }

    // Short trust: false
    // Enables the use of short lived certificates. This will allow for the
    // certificates and keys specified in ssl_certificate, ssl_ca_file and
    // ssl_ca_path to be exchanged and reloaded while the server is running.
    //
    // In an automated environment it is advised to first write the new pem
    // file to a different filename and then to rename it to the configured
    // pem file name to increase performance while swapping the certificate.
    //
    // Disk IO performance can be improved when keeping the certificates and
    // keys stored on a tmpfs (linux) on a system with very high throughput.

    if (j.contains("short-trust")) {
      try {
        m_web_ssl_short_trust = j["short-trust"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'short-trust' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'short-trust' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'short-trust' Defaults will be used.");
    }

    // Allow caching of SSL/TLS sessions, so HTTPS connection from the same
    // client to the same server can be established faster. A configuration
    // value >0 activates session caching. The configuration value is the
    // maximum lifetime of a cached session in seconds. The default is to
    // deactivated session caching.

    // ssl_cache_timeout: -1
    if (j.contains("cache-timeout")) {
      try {
        m_web_ssl_cache_timeout = j["ssl-cache-timeout"].get<long>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'ssl-cache-timeout' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("Failed to read 'ssl-cache-timeout' due to unknown error.");
      }
    }
    else {
      spdlog::debug(" Failed to read 'ssl-cache-timeout' Defaults will be used.");
    }

  } // TLS

  return true;
}

#define TEMPLATE_SAVE_CONFIG                                                                                           \
  "<setup "                                                                                                            \
  " host=\"%s\" "                                                                                                      \
  " port=\"%d\" "                                                                                                      \
  " user=\"%s\" "                                                                                                      \
  " password=\"%s\" "                                                                                                  \
  " rxfilter=\"%s\" "                                                                                                  \
  " rxmask=\"%s\" "                                                                                                    \
  " txfilter=\"%s\" "                                                                                                  \
  " txmask=\"%s\" "                                                                                                    \
  " responsetimeout=\"%lu\" "                                                                                          \
  "/>"

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

bool
CTcpipLink::doSaveConfig(void)
{
  char buf[2048]; // Working buffer

  std::string strRxFilter, strRxMask;
  std::string strTxFilter, strTxMask;
  vscp_writeFilterToString(strRxFilter, &m_filterIn);
  vscp_writeFilterToString(strRxMask, &m_filterIn);
  vscp_writeFilterToString(strTxFilter, &m_filterOut);
  vscp_writeFilterToString(strTxMask, &m_filterOut);

  sprintf(buf,
          TEMPLATE_SAVE_CONFIG,
          m_hostRemote.c_str(),
          m_portRemote,
          m_usernameRemote.c_str(),
          m_passwordRemote.c_str(),
          strRxFilter.c_str(),
          strRxMask.c_str(),
          strTxFilter.c_str(),
          strTxMask.c_str(),
          (long unsigned int) m_responseTimeout);

  FILE *fp;

  fp = fopen(m_path.c_str(), "w");
  if (NULL == fp) {
    spdlog::error("Failed to open configuration file [{}] for write", m_path);
    return false;
  }

  if (strlen(buf) != fwrite(buf, sizeof(char), strlen(buf), fp)) {
    spdlog::error("Failed to write configuration file [{}] ", m_path);
    fclose(fp);
    return false;
  }

  fclose(fp);
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

bool
CTcpipLink::handleHLO(vscpEvent *pEvent)
{
  char buf[512]; // Working buffer
  vscpEventEx ex;

  // Check pointers
  if (NULL == pEvent) {
    spdlog::error("HLO handler: NULL event pointer.");
    return false;
  }

  CHLO hlo;
  if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
    spdlog::error("Failed to parse HLO.");
    return false;
  }

  ex.obid      = 0;
  ex.head      = 0;
  ex.timestamp = vscp_makeTimeStamp();
  vscp_setEventExToNow(&ex); // Set time to current time
  ex.vscp_class = VSCP_CLASS2_PROTOCOL;
  ex.vscp_type  = VSCP2_TYPE_HLO_COMMAND;
  m_guid.writeGUID(ex.GUID);
  /*
      switch (hlo.m_op) {

          case HLO_OP_NOOP:
              // Send positive response
              sprintf(buf,
                      HLO_CMD_REPLY_TEMPLATE,
                      "noop",
                      "OK",
                      "NOOP commaned executed correctly.");

              memset(ex.data, 0, sizeof(ex.data));
              ex.sizeData = strlen(buf);
              memcpy(ex.data, buf, ex.sizeData);

              // Put event in receive queue
              return eventExToReceiveQueue(ex);

          case HLO_OP_READ_VAR:
              if ("REMOTE-HOST" == hlo.m_name) {
                  sprintf(buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "remote-host",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_STRING,
                          vscp_convertToBase64(m_hostRemote).c_str());
              } else if ("REMOTE-PORT" == hlo.m_name) {
                  char ibuf[80];
                  sprintf(ibuf, "%d", m_portRemote);
                  sprintf(buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "remote-port",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                          vscp_convertToBase64(ibuf).c_str());
              } else if ("REMOTE-USER" == hlo.m_name) {
                  sprintf(buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "remote-user",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                          vscp_convertToBase64(m_usernameRemote).c_str());
              } else if ("REMOTE-PASSWORD" == hlo.m_name) {
                  sprintf(buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "remote-password",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                          vscp_convertToBase64(m_passwordRemote).c_str());
              } else if ("TIMEOUT-RESPONSE" == hlo.m_name) {
                  char ibuf[80];
                  sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
                  sprintf(buf,
                          HLO_READ_VAR_REPLY_TEMPLATE,
                          "timeout-response",
                          "OK",
                          VSCP_REMOTE_VARIABLE_CODE_LONG,
                          vscp_convertToBase64(ibuf).c_str());
              }
              break;

          case HLO_OP_WRITE_VAR:
              if ("REMOTE-HOST" == hlo.m_name) {
                  if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                      // Wrong variable type
                      sprintf(buf,
                              HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                              "remote-host",
                              ERR_VARIABLE_WRONG_TYPE,
                              "Variable type should be string.");
                  } else {
                      m_hostRemote = hlo.m_value;
                      sprintf(buf,
                              HLO_READ_VAR_REPLY_TEMPLATE,
                              "enable-sunrise",
                              "OK",
                              VSCP_REMOTE_VARIABLE_CODE_STRING,
                              vscp_convertToBase64(m_hostRemote).c_str());
                  }
              } else if ("REMOTE-PORT" == hlo.m_name) {
                  if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
                      // Wrong variable type
                      sprintf(buf,
                              HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                              "remote-port",
                              ERR_VARIABLE_WRONG_TYPE,
                              "Variable type should be integer.");
                  } else {
                      m_portRemote = vscp_readStringValue(hlo.m_value);
                      char ibuf[80];
                      sprintf(ibuf, "%d", m_portRemote);
                      sprintf(buf,
                              HLO_READ_VAR_REPLY_TEMPLATE,
                              "remote-port",
                              "OK",
                              VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                              vscp_convertToBase64(ibuf).c_str());
                  }
              } else if ("REMOTE-USER" == hlo.m_name) {
                  if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                      // Wrong variable type
                      sprintf(buf,
                              HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                              "remote-port",
                              ERR_VARIABLE_WRONG_TYPE,
                              "Variable type should be string.");
                  } else {
                      m_usernameRemote = hlo.m_value;
                      sprintf(buf,
                              HLO_READ_VAR_REPLY_TEMPLATE,
                              "remote-user",
                              "OK",
                              VSCP_REMOTE_VARIABLE_CODE_STRING,
                              vscp_convertToBase64(m_usernameRemote).c_str());
                  }
              } else if ("REMOTE-PASSWORD" == hlo.m_name) {
                  if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                      // Wrong variable type
                      sprintf(buf,
                              HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                              "remote-password",
                              ERR_VARIABLE_WRONG_TYPE,
                              "Variable type should be string.");
                  } else {
                      m_passwordRemote = hlo.m_value;
                      sprintf(buf,
                              HLO_READ_VAR_REPLY_TEMPLATE,
                              "remote-password!",
                              "OK",
                              VSCP_REMOTE_VARIABLE_CODE_STRING,
                              vscp_convertToBase64(m_passwordRemote).c_str());
                  }
              } else if ("TIMEOUT-RESPONSE¤" == hlo.m_name) {
                  if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
                      // Wrong variable type
                      sprintf(buf,
                              HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                              "timeout-response",
                              ERR_VARIABLE_WRONG_TYPE,
                              "Variable type should be uint32.");
                  } else {
                      m_responseTimeout = vscp_readStringValue(hlo.m_value);
                      char ibuf[80];
                      sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
                      sprintf(buf,
                              HLO_READ_VAR_REPLY_TEMPLATE,
                              "timeout-response",
                              "OK",
                              VSCP_REMOTE_VARIABLE_CODE_UINT32,
                              vscp_convertToBase64(ibuf).c_str());
                  }
              }
              break;

          // Save configuration
          case HLO_OP_SAVE:
              doSaveConfig();
              break;

          // Load configuration
          case HLO_OP_LOAD:
              doLoadConfig();
              break;

          // Connect tyo remote host
          case HLO_OP_LOCAL_CONNECT:
              break;

          // Disconnect from remote host
          case HLO_OP_LOCAL_DISCONNECT:
              break;

          default:
              break;
      };
  */
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// eventExToReceiveQueue
//

bool
CTcpipLink::eventExToReceiveQueue(vscpEventEx &ex)
{
  vscpEvent *pev = new vscpEvent();
  if (!vscp_convertEventExToEvent(pev, &ex)) {
    spdlog::error("Failed to convert event from ex to ev.");
    vscp_deleteEvent(pev);
    return false;
  }
  if (NULL != pev) {
    if (vscp_doLevel2Filter(pev, &m_filterIn)) {
      pthread_mutex_lock(&m_mutexReceiveQueue);
      m_receiveList.push_back(pev);
      sem_post(&m_semReceiveQueue);
      pthread_mutex_unlock(&m_mutexReceiveQueue);
    }
    else {
      vscp_deleteEvent(pev);
    }
  }
  else {
    spdlog::error("Unable to allocate event storage.");
  }
  return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//

bool
CTcpipLink::addEvent2SendQueue(const vscpEvent *pEvent)
{
  pthread_mutex_lock(&m_mutexSendQueue);
  m_sendList.push_back((vscpEvent *) pEvent);
  sem_post(&m_semSendQueue);
  pthread_mutex_lock(&m_mutexSendQueue);
  return true;
}

//////////////////////////////////////////////////////////////////////
// Send worker thread
//

void *
workerThreadSend(void *pData)
{
  bool bRemoteConnectionLost = false;

  CTcpipLink *pObj = (CTcpipLink *) pData;
  if (NULL == pObj) {
    return NULL;
  }

retry_send_connect:

  // Open remote interface
  if (VSCP_ERROR_SUCCESS != pObj->m_srvRemoteSend.doCmdOpen(pObj->m_hostRemote,
                                                            pObj->m_portRemote,
                                                            pObj->m_usernameRemote,
                                                            pObj->m_passwordRemote)) {
    syslog(LOG_ERR,
           "%s %s ",
           VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
           (const char *) "Error while opening remote VSCP TCP/IP "
                          "interface. Terminating!");

    // Give the server some time to become active
    for (int loopcnt = 0; loopcnt < VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME; loopcnt++) {
      sleep(1);
      if (pObj->m_bQuit)
        return NULL;
    }

    goto retry_send_connect;
  }

  syslog(LOG_ERR,
         "%s %s ",
         VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
         (const char *) "Connect to remote VSCP TCP/IP interface [SEND].");

  // Find the channel id
  pObj->m_srvRemoteSend.doCmdGetChannelID(&pObj->txChannelID);

  while (!pObj->m_bQuit) {

    // Make sure the remote connection is up
    if (!pObj->m_srvRemoteSend.isConnected()) {

      if (!bRemoteConnectionLost) {
        bRemoteConnectionLost = true;
        pObj->m_srvRemoteSend.doCmdClose();
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char *) "Lost connection to remote host [SEND].");
      }

      // Wait before we try to connect again
      sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

      if (VSCP_ERROR_SUCCESS != pObj->m_srvRemoteSend.doCmdOpen(pObj->m_hostRemote,
                                                                pObj->m_portRemote,
                                                                pObj->m_usernameRemote,
                                                                pObj->m_passwordRemote)) {
        spdlog::error("{0} {1} ", VSCP_TCPIPLINK_SYSLOG_DRIVER_ID, "Reconnected to remote host [SEND].");

        // Find the channel id
        pObj->m_srvRemoteSend.doCmdGetChannelID(&pObj->txChannelID);

        bRemoteConnectionLost = false;
      }

      continue;
    }

    if ((-1 == vscp_sem_wait(&pObj->m_semSendQueue, 500)) && errno == ETIMEDOUT) {
      continue;
    }

    // Check if there is event(s) to send
    if (pObj->m_sendList.size()) {

      // Yes there are data to send
      pthread_mutex_lock(&pObj->m_mutexSendQueue);
      vscpEvent *pEvent = pObj->m_sendList.front();
      // Check if event should be filtered away
      if (!vscp_doLevel2Filter(pEvent, &pObj->m_filterOut)) {
        pthread_mutex_unlock(&pObj->m_mutexSendQueue);
        continue;
      }
      pObj->m_sendList.pop_front();
      pthread_mutex_unlock(&pObj->m_mutexSendQueue);

      // Only HLO object event is of interst to us
      if ((VSCP_CLASS2_PROTOCOL == pEvent->vscp_class) && (VSCP2_TYPE_HLO_COMMAND == pEvent->vscp_type)) {
        pObj->handleHLO(pEvent);
      }

      if (NULL == pEvent)
        continue;

      // Yes there are data to send
      // Send it out to the remote server

      pObj->m_srvRemoteSend.doCmdSend(pEvent);
      vscp_deleteEvent_v2(&pEvent);
    }
  }

  // Close the channel
  pObj->m_srvRemoteSend.doCmdClose();

  syslog(LOG_ERR,
         "%s %s ",
         VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
         (const char *) "Disconnect from remote VSCP TCP/IP interface [SEND].");

  return NULL;
}

//////////////////////////////////////////////////////////////////////
//                Workerthread Receive - CWrkReceiveTread
//////////////////////////////////////////////////////////////////////

void *
workerThreadReceive(void *pData)
{
  bool bRemoteConnectionLost             = false;
  __attribute__((unused)) bool bActivity = false;

  CTcpipLink *pObj = (CTcpipLink *) pData;
  if (NULL == pObj) {
    return NULL;
  }

retry_receive_connect:

  if (pObj->m_bDebug) {
    printf("Open receive channel host = %s port = %d\n", pObj->m_hostRemote.c_str(), pObj->m_portRemote);
  }

  // Open remote interface
  if (VSCP_ERROR_SUCCESS != pObj->m_srvRemoteReceive.doCmdOpen(pObj->m_hostRemote,
                                                               pObj->m_portRemote,
                                                               pObj->m_usernameRemote,
                                                               pObj->m_passwordRemote)) {
    syslog(LOG_ERR,
           "%s %s ",
           VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
           (const char *) "Error while opening remote VSCP TCP/IP "
                          "interface. Terminating!");

    // Give the server some time to become active
    for (int loopcnt = 0; loopcnt < VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME; loopcnt++) {
      sleep(1);
      if (pObj->m_bQuit)
        return NULL;
    }

    goto retry_receive_connect;
  }

  syslog(LOG_ERR,
         "%s %s ",
         VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
         (const char *) "Connect to remote VSCP TCP/IP interface [RECEIVE].");

  // Set receive filter
  if (VSCP_ERROR_SUCCESS != pObj->m_srvRemoteReceive.doCmdFilter(&pObj->m_filterIn)) {
    spdlog::error("{0} {1} ", VSCP_TCPIPLINK_SYSLOG_DRIVER_ID, "Failed to set receiving filter.");
  }

  // Enter the receive loop
  pObj->m_srvRemoteReceive.doCmdEnterReceiveLoop();

  __attribute__((unused)) vscpEventEx eventEx;
  while (!pObj->m_bQuit) {

    // Make sure the remote connection is up
    if (!pObj->m_srvRemoteReceive.isConnected() ||
        ((vscp_getMsTimeStamp() - pObj->m_srvRemoteReceive.getlastResponseTime()) >
         (VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME * 1000))) {

      if (!bRemoteConnectionLost) {

        bRemoteConnectionLost = true;
        pObj->m_srvRemoteReceive.doCmdClose();
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char *) "Lost connection to remote host [Receive].");
      }

      // Wait before we try to connect again
      sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

      if (VSCP_ERROR_SUCCESS != pObj->m_srvRemoteReceive.doCmdOpen(pObj->m_hostRemote,
                                                                   pObj->m_portRemote,
                                                                   pObj->m_usernameRemote,
                                                                   pObj->m_passwordRemote)) {
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char *) "Reconnected to remote host [Receive].");
        bRemoteConnectionLost = false;
      }

      // Enter the receive loop
      pObj->m_srvRemoteReceive.doCmdEnterReceiveLoop();

      continue;
    }

    // Check if remote server has something to send to us
    vscpEvent e;

    if (CANAL_ERROR_SUCCESS == pObj->m_srvRemoteReceive.doCmdBlockingReceive(&e, 500)) {

      vscpEvent *pEvent = new vscpEvent;
      if (NULL != pEvent) {
        pEvent->sizeData = 0;
        pEvent->pdata    = NULL;

        if (!vscp_copyEvent(pEvent, &e)) {
          syslog(LOG_ERR,
                 "%s %s ",
                 VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                 (const char *) "Failed to copy received event [RECEIVE].");
          continue;
        }

        // Filter is handled at server side. We check so we don't
        // receive things we send ourself.
        if (pObj->txChannelID != pEvent->obid) {
          pthread_mutex_lock(&pObj->m_mutexReceiveQueue);
          pObj->m_receiveList.push_back(pEvent);
          pthread_mutex_unlock(&pObj->m_mutexReceiveQueue);
          sem_post(&pObj->m_semReceiveQueue);
        }
        else {
          vscp_deleteEvent_v2(&pEvent);
        }
      }
    }
  }

  // Close the channel
  pObj->m_srvRemoteReceive.doCmdClose();

  syslog(LOG_ERR,
         "%s %s ",
         VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
         (const char *) "Disconnect from remote VSCP TCP/IP interface [RECEIVE].");

  return NULL;
}
