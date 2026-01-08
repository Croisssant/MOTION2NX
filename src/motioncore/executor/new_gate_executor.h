// MIT License
//
// Copyright (c) 2020 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <functional>
#include <memory>

namespace MOTION {

class GateRegister;
class Logger;

namespace Communication {
class CommunicationLayer;
}

namespace Statistics {
struct RunTimeStats;
}

// Evaluates all registered gates with network measurement support.
class NewGateExecutor {
 public:
  NewGateExecutor(GateRegister& reg, std::function<void(void)> preprocessing_fctn,
                  bool sync_between_setup_and_online,
                  std::function<void(void)> sync_fctn, std::size_t num_threads,
                  std::shared_ptr<Logger> logger);

  NewGateExecutor(GateRegister& reg, std::function<void(void)> preprocessing_fctn,
                  std::size_t num_threads, std::shared_ptr<Logger> logger);

  // Run the setup phases first for all gates before starting with the online phases.
  void evaluate_setup_online(Statistics::RunTimeStats& stats);
  
  // Overloaded version with network measurement support
  void evaluate_setup_online(Statistics::RunTimeStats& stats, Communication::CommunicationLayer& comm);

  // Run setup and online phase of each gate as soon as possible.
  void evaluate(Statistics::RunTimeStats& stats);

 private:
  void evaluate_setup_online_multi_threaded(Statistics::RunTimeStats& stats);
  void evaluate_setup_online_single_threaded(Statistics::RunTimeStats& stats);

  // New methods with network measurement support
  void evaluate_setup_online_multi_threaded(Statistics::RunTimeStats& stats, Communication::CommunicationLayer& comm);
  void evaluate_setup_online_single_threaded(Statistics::RunTimeStats& stats, Communication::CommunicationLayer& comm);

  GateRegister& register_;
  std::function<void(void)> preprocessing_fctn_;
  std::function<void(void)> sync_fctn_;
  std::size_t num_threads_;
  bool sync_between_setup_and_online_;
  std::shared_ptr<Logger> logger_;
};

}  // namespace MOTION
