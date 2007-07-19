# A list of the programs we want to build:
bin_PROGRAMS = remote_chicken

# The sources for each program we define:
remote_chicken_SOURCES = src/scm/repl/remote_chicken.scm

# The following line causes autoconf to become aware of the fact that .scm
# files in the *_SOURCES lists should not be ignored:
.scm.o:

# Specify the extension of our object files:
OBJEXT=o

# Specify how to link object files:
LINK=csc -o bin/$@

# The following lines defines a rule for GNU Make explaining how to build a
# .o file from its associated .scm file:
%.o: %.scm
	csc -c $< -o $@ $(CHICKENFLAGS)
