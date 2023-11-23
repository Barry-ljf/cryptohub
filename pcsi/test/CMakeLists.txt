add_executable(pcsi_sum
        pcsi_sum_test.cpp
        )

add_executable(pcsi_server
        pcsi_server.cpp
        )

add_executable(pcsi_client
        pcsi_client.cpp
        )
target_link_libraries(pcsi_sum PUBLIC
        pcsi
        )

target_link_libraries(pcsi_server PUBLIC
        pcsi
        )

target_link_libraries(pcsi_client PUBLIC
        pcsi
        )

set_target_properties(pcsi_sum
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )

set_target_properties(pcsi_server
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )


set_target_properties(pcsi_client
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)