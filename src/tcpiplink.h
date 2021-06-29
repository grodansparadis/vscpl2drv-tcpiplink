// tcpiplink.h: interface for the socketcan class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2021 Ake Hedman,
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

#if !defined(VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
#define VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_

#define _POSIX

#include <list>
#include <string>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <canal.h>
#include <canal_macro.h>
#include <dllist.h>
#include <guid.h>
#include <vscp.h>
#include <vscpremotetcpif.h>

#include <json.hpp> // Needs C++11  -std=c++11

#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/spdlog.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

// Seconds before trying to reconnect to a broken connection
#define VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME 30

#define VSCP_TCPIPLINK_SYSLOG_DRIVER_ID     "[vscpl2drv-tcpiplink] "
#define VSCP_LEVEL2_DLL_TCPIPLINK_OBJ_MUTEX "___VSCP__DLL_L2TCPIPLINK_OBJ_MUTEX____"
#define VSCP_TCPIPLINK_LIST_MAX_MSG         2048

// Module Local HLO op's
#define HLO_OP_LOCAL_CONNECT    HLO_OP_USER_DEFINED + 0
#define HLO_OP_LOCAL_DISCONNECT HLO_OP_USER_DEFINED + 1

// Forward declarations
class CWrkSendTread;
class CWrkReceiveTread;
class VscpRemoteTcpIf;
class CHLO;

class CTcpipLink {
public:
  /// Constructor
  CTcpipLink();

  /// Destructor
  virtual ~CTcpipLink();

  /*!
      Open
      @return True on success.
   */
  bool open(std::string &path, const cguid &guid);

  /*!
      Flush and close the log file
   */
  void close(void);

  /*!
    Parse HLO object
  */
  bool parseHLO(uint16_t size, uint8_t *inbuf, CHLO *phlo);

  /*!
    Handle high level object
  */
  bool handleHLO(vscpEvent *pEvent);

  /*!
    Read encryption key
    @param path Path to file containing key
    @return true on success, false on failure
  */
  bool readEncryptionKey(const std::string &path);

  /*!
    Load configuration if allowed to do so
    @return true on success, false on failure
  */
  bool doLoadConfig(void);

  /*!
    Save configuration if allowed to do so
  */
  bool doSaveConfig(void);

  /*!
      Put event on receive queue and signal
      that a new event is available

      @param ex Event to send
      @return true on success, false on failure
  */
  bool eventExToReceiveQueue(vscpEventEx &ex);

  /*!
      Add event to send queue
   */
  bool addEvent2SendQueue(const vscpEvent *pEvent);

public:
  /// Parsed Config file
  json m_j_config;

  /// Debug flag
  bool m_bDebug;

  /// Write flags
  bool m_bWriteEnable;

  /// Run flag
  bool m_bQuit;

  // Our GUID
  cguid m_guid;

  // The default random encryption key
  uint8_t m_vscp_key[32] = { 0x2d, 0xbb, 0x07, 0x9a, 0x38, 0x98, 0x5a, 0xf0, 0x0e, 0xbe, 0xef,
                             0xe2, 0x2f, 0x9f, 0xfa, 0x0e, 0x7f, 0x72, 0xdf, 0x06, 0xeb, 0xe4,
                             0x45, 0x63, 0xed, 0xf4, 0xa1, 0x07, 0x3c, 0xab, 0xc7, 0xd4 };

  /////////////////////////////////////////////////////////
  //                      Logging
  /////////////////////////////////////////////////////////

  bool m_bConsoleLogEnable;                    // True to enable logging
  spdlog::level::level_enum m_consoleLogLevel; // log level
  std::string m_consoleLogPattern;             // log file pattern

  bool m_bFileLogEnable;                    // True to enable logging
  spdlog::level::level_enum m_fileLogLevel; // log level
  std::string m_fileLogPattern;             // log file pattern
  std::string m_path_to_log_file;           // Path to logfile
  uint32_t m_max_log_size;                  // Max size for logfile before rotating occures
  uint16_t m_max_log_files;                 // Max log files to keep

  // Path to configuration file
  std::string m_path;

  /// server supplied host
  std::string m_hostRemote;

  /// Server supplied port
  int m_portRemote;

  /// Server supplied username
  std::string m_usernameRemote;

  /// Server supplied password
  std::string m_passwordRemote;

  /// Send channel id
  uint32_t txChannelID;

  /// Filter for receive
  vscpEventFilter m_filterIn;

  /// Filter for transmitt
  vscpEventFilter m_filterOut;

  // TCP/IP link response timeout
  uint32_t m_responseTimeout;

  // TLS
  std::string m_web_ssl_certificate;
  std::string m_web_ssl_certificate_chain;
  bool m_web_ssl_verify_peer;
  std::string m_web_ssl_ca_path;
  std::string m_web_ssl_ca_file;
  uint16_t m_web_ssl_verify_depth;
  bool m_web_ssl_default_verify_paths;
  std::string m_web_ssl_cipher_list;
  uint8_t m_web_ssl_protocol_version;
  bool m_web_ssl_short_trust;
  long m_web_ssl_cache_timeout;

  /// Worker threads
  pthread_t m_pthreadSend;
  pthread_t m_pthreadReceive;

  /// VSCP remote server send interface
  VscpRemoteTcpIf m_srvRemoteSend;

  /// VSCP remote server receive interface
  VscpRemoteTcpIf m_srvRemoteReceive;

  // Queue
  std::list<vscpEvent *> m_sendList;
  std::list<vscpEvent *> m_receiveList;

  /*!
      Event object to indicate that there is an event in the output queue
   */
  sem_t m_semSendQueue;
  sem_t m_semReceiveQueue;

  // Mutex to protect the output queue
  pthread_mutex_t m_mutexSendQueue;
  pthread_mutex_t m_mutexReceiveQueue;
};

#endif // !defined(VSCPTCPIPLINK_H__6F5CD90E_ACF7_459A_9ACB_849A57595639__INCLUDED_)
