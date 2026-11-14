# Man pages: <page>.md (pandoc's man format) is converted with
#   pandoc -s -t man <page>.md -o <page>
# when the driver is built and installed in share/man/man<section>.

include(GNUInstallDirs)

set(MAN_PAGES vscpl2drv-tcpiplink.1)

find_program(PANDOC_EXECUTABLE pandoc DOC "pandoc, converts the Markdown man pages")
if(NOT PANDOC_EXECUTABLE)
  message(WARNING "pandoc was not found, the man pages are not built. Install pandoc (e.g. apt install pandoc).")
  return()
endif()

set(_man_outputs "")
foreach(_page IN LISTS MAN_PAGES)
  string(REGEX MATCH "[1-8]$" _section "${_page}")
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${_page}
    COMMAND ${PANDOC_EXECUTABLE} -s -t man ${CMAKE_CURRENT_SOURCE_DIR}/${_page}.md -o ${CMAKE_CURRENT_BINARY_DIR}/${_page}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${_page}.md
    COMMENT "Man page ${_page}"
    VERBATIM)
  list(APPEND _man_outputs ${CMAKE_CURRENT_BINARY_DIR}/${_page})
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${_page} DESTINATION ${CMAKE_INSTALL_MANDIR}/man${_section})
endforeach()

add_custom_target(man ALL DEPENDS ${_man_outputs})
