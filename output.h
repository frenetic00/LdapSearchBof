#ifdef BOF

#define totalPageSize 4096
// Initialise global variables with non-zero values
// This puts variables in the data segment as opposed to BSS
// BOF can't handle BSS - https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/common/base.c#L9
WORD currentPageSize = 1;
char *page = (char *)1;

void print_page(BOOL isFinal)
{
    // Print page
    BeaconOutput(CALLBACK_OUTPUT, page, currentPageSize);

    // Reset the page
    currentPageSize = 0;
    memset(page, 0, totalPageSize);

    // Free the memory if it's the last page
    if (isFinal)
    {
        MSVCRT$free(page);
    }
}

void commonPrintf(const char *format, ...)
{
    // Fetch the variable number of arguments using the va_lsit macro
    // https://www.unf.edu/~cwinton/html/cop3601/s10/class.notes/C6-ellipsis.pdf
    va_list args;           // Declare a list pointer
    va_start(args, format); // Start after the "format" variable

    // The "v" family of prinf functions can accept va_lists as an argument to construct a string
    // vsnprintf always writes a null terminator, even if it truncates the output
    // NULL pointer for buffer and a size of 0 gives us the output lenght including a null terminator
    WORD lineSize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    // BeaconPrintf(CALLBACK_OUTPUT, "Line size: %i", lineSize);

    // Catch any encoding errors from vsnprintf
    if (lineSize == -1)
    {
        return;
    }

    // Prepare the char buffer on the heap
    // char* lineToAdd = (char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, lineSize);
    char *lineToAdd = (char *)MSVCRT$calloc(lineSize, sizeof(char));
    // Add the string to our buffer
    va_start(args, format);
    int result = MSVCRT$vsnprintf(lineToAdd, lineSize, format, args);
    va_end(args);

    // Store line in page
    if (lineSize + currentPageSize < totalPageSize)
    {
        MSVCRT$memcpy(page + currentPageSize, lineToAdd, lineSize);
        currentPageSize += lineSize;
    }
    // Page if full
    else
    {
        char *linePtr = lineToAdd;

        while (lineSize != 0)
        {
            // How much space is left in a page
            int spaceRemaining = totalPageSize - currentPageSize;

            // If our line is less than the remaining space in our buffer
            // set spaceRemaining to the line size to avoid copying more bytes
            // than what we have in lineSize
            if (lineSize < spaceRemaining)
            {
                spaceRemaining = lineSize;
            }

            // Copy a segment of the line in to the page buffer
            MSVCRT$memcpy(page + currentPageSize, linePtr, spaceRemaining);

            // Adjust page size tracker
            currentPageSize += spaceRemaining;

            // Print page if the page is full
            if (currentPageSize == totalPageSize)
            {
                print_page(FALSE);
            }

            // Adjust pointer for lineToAdd so we can
            // start after what we just printed
            linePtr += spaceRemaining;
            lineSize -= spaceRemaining;
        }
    }

    // Free heap resouce
    // KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lineToAdd);
    MSVCRT$free(lineToAdd);
}

#else

#define commonPrintf printf

#endif
