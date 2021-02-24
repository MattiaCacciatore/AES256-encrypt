# MACROS
# Compiler
CC = g++
# Compiler standard
STD = -std=c++14
#Debug flag
DEBUG = -ggdb
# Compiler flags
CFLAGS = -Wall -pedantic -Werror -Wextra 
# -fsanitize=address
# Execute name
EXEC = AES256
# Main name
MAIN = $(EXEC)_main.cpp
# Functions name
FUNCTIONS = $(EXEC)_functions.cpp
# Source files
SOURCES = $(MAIN) $(EXEC).h $(FUNCTIONS)
# Object files
OBJ = $(EXEC)_main.o $(EXEC)_functions.o
TARF = $(EXEC).tgz

# Dependencies
$(EXEC): $(OBJ)
	$(COMP) -o $(EXEC) $(STD) $(DEBUG) $(WARN) $(OBJ)

$(EXEC).o: $(SOURCES)
	$(COMP) -c $(STD) $(WARN) $(MAIN) $(FUNCTIONS)

# Make clean to remove all .o files
clean:
	/bin/rm -f *.o $(EXEC)

tgz: clean $(SOURCES)
	cd .. ; tar cvzf $(TARF) $(EXEC) 
