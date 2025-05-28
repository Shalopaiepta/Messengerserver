cmake_minimum_required(VERSION 3.10)
project(Server)

# Устанавливаем стандарт C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Указываем исходный файл сервера
add_executable(server messengerserver.cpp)

# Для Windows подключаем библиотеку ws2_32
if(WIN32)
    target_link_libraries(server ws2_32)
endif()

# Настройка путей для SQLite
set(SQLITE3_INCLUDE_DIR "C:/CourseWorkProjectMessenger/Libraries/sqlite/include")
set(SQLITE3_LIBRARY_DIR "C:/CourseWorkProjectMessenger/Libraries/sqlite/lib")
set(SQLITE3_BINARY_DIR "C:/CourseWorkProjectMessenger/Libraries/sqlite/bin")
set(SQLITE3_LIBRARY "${SQLITE3_LIBRARY_DIR}/sqlite3.lib")
set(SQLITE3_DLL "${SQLITE3_BINARY_DIR}/sqlite3.dll")

# Проверяем наличие заголовочного файла
if(NOT EXISTS "${SQLITE3_INCLUDE_DIR}/sqlite3.h")
    message(FATAL_ERROR "sqlite3.h not found in ${SQLITE3_INCLUDE_DIR}")
endif()

# Проверяем наличие библиотеки
find_library(SQLITE3_LIB NAMES sqlite3 PATHS ${SQLITE3_LIBRARY_DIR})
if(NOT SQLITE3_LIB)
    message(FATAL_ERROR "SQLite3 library not found in ${SQLITE3_LIBRARY_DIR}")
endif()

# Проверяем наличие DLL
if(NOT EXISTS "${SQLITE3_DLL}")
    message(FATAL_ERROR "sqlite3.dll not found in ${SQLITE3_BINARY_DIR}")
endif()

# Добавляем пути к заголовкам и библиотеке SQLite
target_include_directories(server PRIVATE ${SQLITE3_INCLUDE_DIR})
target_link_libraries(server ${SQLITE3_LIB})

# Копируем sqlite3.dll в выходную директорию
add_custom_command(TARGET server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${SQLITE3_DLL}"
        "$<TARGET_FILE_DIR:server>"
    COMMENT "Copying sqlite3.dll to output directory"
)