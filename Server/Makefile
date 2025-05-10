.PHONY: all doxy clean

# Компилятор и флаги
CXX        = g++
CXXFLAGS   = -Wall -fPIC -fsanitize=address
LDLIBS     = -lboost_program_options -lcrypto++ -lboost_filesystem
QT_CFLAGS  = $(shell pkg-config --cflags Qt5Core Qt5Widgets Qt5Sql)
QT_LIBS    = $(shell pkg-config --libs   Qt5Core Qt5Widgets Qt5Sql)

# Параметры путей
SRCDIR    ?= src
BUILDDIR  ?= build
TARGET     = server

# Находим все исходники и хедеры
SOURCES    := $(wildcard $(SRCDIR)/*.cpp)
HEADERS    := $(wildcard $(SRCDIR)/*.h)

# moc‑заголовки (те, где есть Q_OBJECT)
MOC_HEADERS := $(SRCDIR)/communicator.h $(SRCDIR)/serverwindow.h
# пути к сгенерированным moc_*.cpp
MOC_SRCS    := $(patsubst $(SRCDIR)/%.h,$(BUILDDIR)/moc_%.cpp,$(MOC_HEADERS))
# и их .o
MOC_OBJS    := $(patsubst $(BUILDDIR)/%.cpp,$(BUILDDIR)/%.o,$(MOC_SRCS))

# все объекты: из .cpp и из moc_*.cpp
OBJECTS    := $(patsubst $(SRCDIR)/%.cpp, $(BUILDDIR)/%.o, $(SOURCES)) $(MOC_OBJS)

# Цель по умолчанию
all: $(TARGET)

# Сборка целевого бинарника
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) $(CXXFLAGS) $(LDLIBS) $(QT_LIBS) -o $@

# Компиляция каждого cpp → o (исходники из src), пересобирать при изменении заголовков
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp $(HEADERS)
	@mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -c $< -o $@

# Компиляция каждого cpp → o (moc_*.cpp в build)
$(BUILDDIR)/%.o: $(BUILDDIR)/%.cpp
	@mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -c $< -o $@

# Генерация moc_*.cpp из заголовков с Q_OBJECT
$(BUILDDIR)/moc_%.cpp: $(SRCDIR)/%.h
	@mkdir -p $(BUILDDIR)
	moc $(QT_CFLAGS) $< -o $@

# Генерация документации
doxy:
	doxygen

# Очистка
clean:
	rm -rf $(BUILDDIR) $(TARGET)
