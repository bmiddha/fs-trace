#include <node.h>
#include <fcntl.h>
#include "trace_exec.cc"

using v8::Array;
using v8::Context;
using v8::Exception;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

const char *ToCString(const String::Utf8Value &value) { return *value ? *value : "<string conversion failed>"; }

void Method(const FunctionCallbackInfo<Value> &args)
{
  Isolate *isolate = args.GetIsolate();

  if (args.Length() < 2)
  {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8(isolate, "Wrong number of arguments, expected 2").ToLocalChecked()));
    return;
  }

  if (!args[0]->IsArray())
  {
    isolate->ThrowException(
        Exception::TypeError(String::NewFromUtf8(isolate, "arg[0] must be an array of strings").ToLocalChecked()));
    return;
  }

  if (!args[1]->IsFunction())
  {
    isolate->ThrowException(
        Exception::TypeError(String::NewFromUtf8(isolate, "arg[1] must be a function").ToLocalChecked()));
    return;
  }

  Local<Array> trace_args_v8 = Local<Array>::Cast(args[0]);
  for (uint32_t i = 0; i < trace_args_v8->Length(); i++)
  {
    if (!trace_args_v8->Get(isolate->GetCurrentContext(), i).ToLocalChecked()->IsString())
    {
      isolate->ThrowException(
          Exception::TypeError(String::NewFromUtf8(isolate, "arg[0] must be an array of strings").ToLocalChecked()));
      return;
    }
  }
  Local<Function> cb = Local<Function>::Cast(args[1]);

  // convert trace_args_v8 to char**, add NULL at the end
  char **trace_args = (char **)malloc((trace_args_v8->Length() + 1) * sizeof(char *));
  for (uint32_t i = 0; i < trace_args_v8->Length(); i++)
  {
    String::Utf8Value arg(isolate, trace_args_v8->Get(isolate->GetCurrentContext(), i).ToLocalChecked());
    trace_args[i] = strdup(ToCString(arg));
  }
  trace_args[trace_args_v8->Length()] = NULL;

  printf("trace_args:");
  for (uint32_t i = 0; i < trace_args_v8->Length(); i++)
  {
    printf(" %s", trace_args[i]);
  }
  printf("\n");

  Local<Context> context = isolate->GetCurrentContext();

  int pipe_fd[2];
  if (pipe(pipe_fd) == -1)
  {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "pipe error").ToLocalChecked()));
  }

  pid_t child = fork();
  if (child == 0)
  {
    close(pipe_fd[0]); // close read end
    // dup2(pipe_fd[1], 1);
    // dup2(pipe_fd[1], 2);
    dup2(pipe_fd[1], 3);

    trace_exec(trace_args[0], trace_args);
  }
  else if (child > 0)
  {
    // Parent process

    close(pipe_fd[1]); // close write end

    char buffer[1024];
    std::string line;
    while (true)
    {
      ssize_t bytesRead = read(pipe_fd[0], buffer, sizeof(buffer) - 1);
      if (bytesRead <= 0)
      {
        break; // End of data or error
      }
      buffer[bytesRead] = '\0'; // Null-terminate the buffer

      for (ssize_t i = 0; i < bytesRead; ++i)
      {
        if (buffer[i] == '\n')
        {
          // Call the callback with the current line
          const unsigned argc = 1;
          char *line_cstr = strdup(line.c_str());
          // printf("line: %s\n", line_cstr);
          Local<Value> argv[argc] = {String::NewFromUtf8(isolate, line_cstr).ToLocalChecked()};
          cb->Call(context, Null(isolate), argc, argv).ToLocalChecked();
          line.clear(); // Clear the line for the next input
        }
        else
        {
          line += buffer[i]; // Append character to the line
        }
      }
    }

    // Handle any remaining data in the line buffer
    if (!line.empty())
    {
      const unsigned argc = 1;
      Local<Value> argv[argc] = {String::NewFromUtf8(isolate, line.c_str()).ToLocalChecked()};
      cb->Call(context, Null(isolate), argc, argv).ToLocalChecked();
    }

    close(pipe_fd[0]); // Close read end
  }
  else
  {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "fork error").ToLocalChecked()));
  }
}

void Initialize(Local<Object> exports) { NODE_SET_METHOD(exports, "exec", Method); }

NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
