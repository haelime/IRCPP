TARGET = ircserv

CXX = c++

CXXFLAGS = -Wall -Werror -Wextra -std=c++98 -DNODEBUG\
# -g -fsanitize=address # DEBUG

CWD = $(shell pwd)
SRCDIR = $(CWD)/srcs

SOURCE = $(SRCDIR)/main.cpp \
		 $(SRCDIR)/Server.cpp \
		 $(SRCDIR)/ClientData.cpp \
		 $(SRCDIR)/Channel.cpp \
		 $(SRCDIR)/Logger.cpp \
		 $(SRCDIR)/SignalHandler.cpp \

OBJECTS = $(SOURCE:.cpp=.o)\

HEADERS = -I./include/\

LIBPATH =

# Kqueue support for Linux (libkqueue-dev package required)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    HEADERS += -I/usr/include/kqueue/
    LIBPATH += -L/usr/lib/x86_64-linux-gnu/ -lkqueue
endif

all: $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(HEADERS)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(HEADERS) $(LIBPATH)

clean:
	rm -f $(OBJECTS)

fclean:
	rm -f $(TARGET) $(OBJECTS)

re: fclean all

.PHONY: all clean