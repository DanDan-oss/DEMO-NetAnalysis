include_directories(./include)
file(GLOB SRC_FILE "./include/*.c")
add_executable(dpi.out ./Main.c ${SRC_FILE})
target_link_libraries(dpi.out pcap)
