// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include <fmt/format.h>
#include <cmath>
#include <sstream>
#include "run_time_stats.h"
#include "../communication/communication_layer.h"
#include "../communication/transport.h"

namespace MOTION {
namespace Statistics {

static double compute_ms(const RunTimeStats::time_point_pair& tpp) {
  std::chrono::duration<double, std::milli> ms = tpp.second - tpp.first;
  return ms.count();
}

const RunTimeStats::time_point_pair& RunTimeStats::get(StatID id) const {
  return data_.at(static_cast<std::size_t>(id));
}

const RunTimeStats::NetworkStats& RunTimeStats::get_network_stats(StatID id) const {
  return network_data_.at(static_cast<std::size_t>(id));
}

RunTimeStats::NetworkStats RunTimeStats::sum_transport_stats(const std::vector<Communication::TransportStatistics>& stats) const {
  NetworkStats result{};
  for (const auto& stat : stats) {
    result.bytes_sent += stat.num_bytes_sent;
    result.bytes_received += stat.num_bytes_received;
    result.messages_sent += stat.num_messages_sent;
    result.messages_received += stat.num_messages_received;
  }
  return result;
}

template <RunTimeStats::StatID ID>
void RunTimeStats::record_network_start(Communication::CommunicationLayer& comm) {
  auto transport_stats = comm.get_transport_statistics();
  auto& baseline = network_baselines_[static_cast<std::size_t>(ID)];
  baseline = sum_transport_stats(transport_stats);
}

template <RunTimeStats::StatID ID>
void RunTimeStats::record_network_end(Communication::CommunicationLayer& comm) {
  auto transport_stats = comm.get_transport_statistics();
  auto current_stats = sum_transport_stats(transport_stats);
  auto& baseline = network_baselines_[static_cast<std::size_t>(ID)];
  auto& result = network_data_[static_cast<std::size_t>(ID)];
  
  result.bytes_sent = current_stats.bytes_sent - baseline.bytes_sent;
  result.bytes_received = current_stats.bytes_received - baseline.bytes_received;
  result.messages_sent = current_stats.messages_sent - baseline.messages_sent;
  result.messages_received = current_stats.messages_received - baseline.messages_received;
}

// Explicit template instantiations for the StatIDs we care about
template void RunTimeStats::record_network_start<RunTimeStats::StatID::preprocessing>(Communication::CommunicationLayer& comm);
template void RunTimeStats::record_network_end<RunTimeStats::StatID::preprocessing>(Communication::CommunicationLayer& comm);
template void RunTimeStats::record_network_start<RunTimeStats::StatID::gates_setup>(Communication::CommunicationLayer& comm);
template void RunTimeStats::record_network_end<RunTimeStats::StatID::gates_setup>(Communication::CommunicationLayer& comm);
template void RunTimeStats::record_network_start<RunTimeStats::StatID::gates_sync>(Communication::CommunicationLayer& comm);
template void RunTimeStats::record_network_end<RunTimeStats::StatID::gates_sync>(Communication::CommunicationLayer& comm);
template void RunTimeStats::record_network_start<RunTimeStats::StatID::gates_online>(Communication::CommunicationLayer& comm);
template void RunTimeStats::record_network_end<RunTimeStats::StatID::gates_online>(Communication::CommunicationLayer& comm);

template <typename C>
typename C::value_type at(const C& container, RunTimeStats::StatID id) {
  return container.at(static_cast<std::size_t>(id));
}

std::string RunTimeStats::print_human_readable() const {
  std::array<double, std::tuple_size_v<decltype(data_)>> ms;
  std::transform(data_.cbegin(), data_.cend(), ms.begin(), compute_ms);
  auto max = *std::max_element(ms.cbegin(), ms.cend());
  auto width = static_cast<std::size_t>(std::ceil(std::log10(max))) + 4;

  // Get network stats for all phases
  auto preprocessing_net = get_network_stats(StatID::preprocessing);
  auto setup_net = get_network_stats(StatID::gates_setup);
  auto sync_net = get_network_stats(StatID::gates_sync);
  auto online_net = get_network_stats(StatID::gates_online);

  std::stringstream ss;
  ss << fmt::format("MT Presetup         {:{}.3f} ms\n", at(ms, StatID::mt_presetup), width)
     << fmt::format("MT Setup            {:{}.3f} ms\n", at(ms, StatID::mt_setup), width)
     << fmt::format("SP Presetup         {:{}.3f} ms\n", at(ms, StatID::sp_presetup), width)
     << fmt::format("SP Setup            {:{}.3f} ms\n", at(ms, StatID::sp_setup), width)
     << fmt::format("SB Presetup         {:{}.3f} ms\n", at(ms, StatID::sb_presetup), width)
     << fmt::format("SB Setup            {:{}.3f} ms\n", at(ms, StatID::sb_setup), width)
     << fmt::format("Base OTs            {:{}.3f} ms\n", at(ms, StatID::base_ots), width)
     << fmt::format("OT Extension Setup  {:{}.3f} ms\n", at(ms, StatID::ot_extension_setup), width)
     << fmt::format("-------------------------\n")
     << fmt::format("Preprocessing Total {:{}.3f} ms", at(ms, StatID::preprocessing), width);
  
  // Add network stats for preprocessing if available 
  if (preprocessing_net.bytes_sent > 0 || preprocessing_net.bytes_received > 0) {
    ss << fmt::format(" (Sent: {} bytes, Recv: {} bytes)", 
                      preprocessing_net.bytes_sent, preprocessing_net.bytes_received);
  }
  ss << "\n"
     << fmt::format("Gates Setup         {:{}.3f} ms", at(ms, StatID::gates_setup), width);
  
  // Add network stats for gates_setup if available 
  if (setup_net.bytes_sent > 0 || setup_net.bytes_received > 0) {
    ss << fmt::format(" (Sent: {} bytes, Recv: {} bytes)", 
                      setup_net.bytes_sent, setup_net.bytes_received);
  }
  ss << "\n";
  
  // Add gates_sync phase
  if (sync_net.bytes_sent > 0 || sync_net.bytes_received > 0 || at(ms, StatID::gates_sync) > 0) {
    ss << fmt::format("Gates Sync          {:{}.3f} ms", at(ms, StatID::gates_sync), width);
    if (sync_net.bytes_sent > 0 || sync_net.bytes_received > 0) {
      ss << fmt::format(" (Sent: {} bytes, Recv: {} bytes)", 
                        sync_net.bytes_sent, sync_net.bytes_received);
    }
    ss << "\n";
  }
  
  ss << fmt::format("Gates Online        {:{}.3f} ms", at(ms, StatID::gates_online), width);
  
  // Add network stats for gates_online if available
  if (online_net.bytes_sent > 0 || online_net.bytes_received > 0) {
    ss << fmt::format(" (Sent: {} bytes, Recv: {} bytes)", 
                      online_net.bytes_sent, online_net.bytes_received);
  }
  ss << "\n";
  
  ss << fmt::format("-------------------------\n")
     << fmt::format("Circuit Evaluation  {:{}.3f} ms\n", at(ms, StatID::evaluate), width);
  return ss.str();
}

}  // namespace Statistics
}  // namespace MOTION
