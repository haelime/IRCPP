TARGET = ircserv

CXX = c++
CXXFLAGS = -Wall -Werror -Wextra

SOURCE = $(wildcard *.cpp)
OBJECTS = $(SOURCE:.cpp=.o)
headers = $(wildcard *.hpp)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(OBJECTS)

fclean:
	rm -f $(TARGET) $(OBJECTS)
	
.PHONY: all clean