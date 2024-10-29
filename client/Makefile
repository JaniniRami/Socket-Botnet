CXX = g++

CXXFLAGS = -Iinclude -std=c++11 

TARGET = client_tsamgroupA3_56

OBJS = client.o 

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

client.o: client.cpp
	$(CXX) $(CXXFLAGS) -c client.cpp -o client.o

# Clean the compiled files
clean:
	rm -f $(TARGET) *.o src/*.o
