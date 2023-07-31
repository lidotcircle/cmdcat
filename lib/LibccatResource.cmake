function(create_resource_c res_file c_variable output_file)
   # Create empty output file
    file(WRITE ${output_file} "")
    # Read the resource file
    file(READ ${res_file} filedata HEX)
    # Convert hex data for C compatibility
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," filedata ${filedata})
    # Append data to output file
    file(APPEND ${output_file} "const unsigned char ${c_variable}[] = {${filedata}};\nconst unsigned ${c_variable}_size = sizeof(${c_variable});\n")
endfunction()

create_resource_c("${LIB_FILENAME}" libccat_so_raw "${HEADER_FILENAME}")
