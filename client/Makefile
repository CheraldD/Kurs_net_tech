.PHONY: all doxy clean

# Компилятор и флаги
CXX = g++
CXXFLAGS = -Wall -fPIC 
LDLIBS = -lboost_program_options -lcrypto++ -lboost_filesystem
QT_CFLAGS = $(shell pkg-config --cflags Qt5Core Qt5Sql)
QT_LIBS = $(shell pkg-config --libs Qt5Core Qt5Sql)

# Параметры путей
SRCDIR ?= src
BUILDDIR ?= build
TARGET = client

# Находим все исходники и хедеры
SOURCES := $(wildcard $(SRCDIR)/*.cpp)
HEADERS := $(wildcard $(SRCDIR)/*.h)
OBJECTS := $(patsubst $(SRCDIR)/%.cpp, $(BUILDDIR)/%.o, $(SOURCES))

# Цель по умолчанию
all: $(TARGET)

# Сборка целевого бинарника
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) $(CXXFLAGS) $(LDLIBS) $(QT_LIBS) -o $@

# Компиляция каждого cpp → o
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -c $< -o $@

# Генерация документации
doxy:
	doxygen

# Очистка
clean:
	rm -rf $(BUILDDIR) $(TARGET)
