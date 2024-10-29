CXX = g++

CXXFLAGS = -Iinclude -std=c++11 

TARGET = tsamgroupA3_56

OBJS = server.o 

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

server.o: server.cpp
	$(CXX) $(CXXFLAGS) -c server.cpp -o server.o

# Clean the compiled files
clean:
	rm -f $(TARGET) *.o src/*.o
