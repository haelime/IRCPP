TARGET = ircserv

CXX = c++
CXXFLAGS = -Wall -Werror -Wextra -std=c++98 -g

CWD = $(shell pwd)
SRCDIR = $(CWD)/srcs

SOURCE = $(SRCDIR)/main.cpp \
		 $(SRCDIR)/Server.cpp \
		 $(SRCDIR)/ClientData.cpp \
		 $(SRCDIR)/Channel.cpp \
		 $(SRCDIR)/Logger.cpp \

OBJECTS = $(SOURCE:.cpp=.o)\

HEADERS = -I./include/\


all: $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(HEADERS)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(HEADERS)

clean:
	rm -f $(OBJECTS)

fclean:
	rm -f $(TARGET) $(OBJECTS)

re: fclean all

.PHONY: all clean