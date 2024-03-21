TARGET = ircserv

CXX = c++
CXXFLAGS = -Wall -Werror -Wextra

SOURCE = $(wildcard ./srcs/*.cpp)
OBJECTS = $(SOURCE:.cpp=.o)

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