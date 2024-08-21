// SPDX-License-Identifier: MIT
#ifndef FFKX_BPF_HPP
#define FFKX_BPF_HPP

#include <absl/container/flat_hash_map.h>
#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <bpf/libbpf.h>

#include <Utility.hpp>
#include <optional>
#include <string_view>
#include <utility>

#define INIT_LIBBPF_OPTS(opts)      \
  do {                              \
    memset(&opts, 0, sizeof(opts)); \
    opts.sz = sizeof(opts);         \
  } while (0)

namespace ffkx {
namespace bpf {

struct Program {
 public:
  constexpr explicit Program(struct bpf_program *prog = nullptr) : prog_(prog) {}
  Program(const Program&) = default;
  Program& operator=(const Program&) = default;
  Program(Program&& p) = default;
  Program& operator=(Program&& p) = default;
  ~Program() = default;

  struct bpf_program *Get() const { return prog_; }

  int GetRawFd() const { return bpf_program__fd(prog_); }

  explicit operator bool() const { return prog_; }

 private:
  struct bpf_program *prog_;
};

class Map {
 public:
  constexpr explicit Map(struct bpf_map *map = nullptr) : map_(map) {}
  Map(const Map&) = default;
  Map& operator=(const Map&) = default;
  Map(Map&& p) = default;
  Map& operator=(Map&& p) = default;
  ~Map() = default;

  struct bpf_map *Get() const { return map_; }

  int GetRawFd() const { return bpf_map__fd(map_); }

  explicit operator bool() const { return map_; }

 private:
  struct bpf_map *map_;
};

class Object {
 public:
  explicit Object() = default;
  Object(const Object&) = default;
  Object& operator=(const Object&) = default;
  Object(Object&&) = default;
  Object& operator=(Object&&) = default;

  virtual absl::Status Open(const struct bpf_object_open_opts *opts = nullptr) = 0;
  virtual absl::Status Load() = 0;
  virtual absl::Status Attach() = 0;
  virtual absl::Status Detach() = 0;
  virtual void Destroy() = 0;

 protected:
  ~Object() = default;

  absl::flat_hash_map<std::string, Map> maps_;
  absl::flat_hash_map<std::string, Program> progs_;
};

template <typename Skeleton, typename Derived>
class ObjectLoader {
 public:
  explicit ObjectLoader() = default;
  ObjectLoader(const ObjectLoader&) = default;
  ObjectLoader& operator=(const ObjectLoader&) = default;
  ObjectLoader(ObjectLoader&&) = default;
  ObjectLoader& operator=(ObjectLoader&&) = default;
  ~ObjectLoader() = default;

  absl::Status ObjectConfigure(Skeleton& skel) {
    FFKX_DERIVED_HAS_METHOD(Derived, ObjectConfigure);
    return static_cast<Derived *>(this)->ObjectConfigure(skel);
  }

  absl::Status ObjectAttach(Skeleton& skel) {
    FFKX_DERIVED_HAS_METHOD(Derived, ObjectAttach);
    return static_cast<Derived *>(this)->ObjectAttach(skel);
  }

  absl::Status ObjectDetach(Skeleton& skel) {
    FFKX_DERIVED_HAS_METHOD(Derived, ObjectDetach);
    return static_cast<Derived *>(this)->ObjectDetach(skel);
  }

  void ObjectDestroy(Skeleton& skel) {
    FFKX_DERIVED_HAS_METHOD(Derived, ObjectDestroy);
    static_cast<Derived *>(this)->ObjectDestroy(skel);
  }
};

namespace detail {

template <typename Skeleton>
class LoaderImplDefault : public ObjectLoader<Skeleton, LoaderImplDefault<Skeleton>> {
 public:
  absl::Status ObjectConfigure(Skeleton&) { return absl::OkStatus(); }

  absl::Status ObjectAttach(Skeleton&) { return absl::OkStatus(); }

  absl::Status ObjectDetach(Skeleton&) { return absl::OkStatus(); }

  void ObjectDestroy(Skeleton&) {}
};

}  // namespace detail

template <typename Skel, template <typename> typename LoaderImpl = detail::LoaderImplDefault>
class Skeleton : public Object, public LoaderImpl<Skeleton<Skel, LoaderImpl>> {
  using Loader = ObjectLoader<Skeleton, LoaderImpl<Skeleton<Skel, LoaderImpl>>>;

 public:
  constexpr explicit Skeleton() : skel_(nullptr), loader_(static_cast<Loader *>(this)) {}
  Skeleton(const Skeleton&) = delete;
  Skeleton& operator=(const Skeleton&) = delete;

  Skeleton(Skeleton&& s) noexcept {
    skel_ = std::exchange(s.skel_, nullptr);
    progs_ = std::move(s.progs_);
    maps_ = std::move(s.maps_);
  }

  Skeleton& operator=(Skeleton&& s) noexcept {
    if (this != &s) {
      skel_ = std::exchange(s.skel_, nullptr);
      progs_ = std::move(s.progs_);
      maps_ = std::move(s.maps_);
    }
    return *this;
  }

  ~Skeleton() {
    if (skel_) {
      Skel::destroy(skel_);
    }
  }

  virtual absl::Status Open(const struct bpf_object_open_opts *opts = nullptr) override final {
    if (skel_) {
      return absl::AlreadyExistsError("Skeleton has been opened already.");
    }

    skel_ = Skel::open(opts);
    int err = libbpf_get_error(skel_);
    if (err) {
      skel_ = nullptr;
      return absl::ErrnoToStatus(errno, "Failed to open BPF object.");
    }
    return absl::OkStatus();
  }

  virtual absl::Status Load() override final {
    auto ret = loader_->ObjectConfigure(*this);
    if (!ret.ok()) {
      return ret;
    }

    int err = Skel::load(skel_);
    if (err) {
      return absl::ErrnoToStatus(errno, "Failed to load BPF object.");
    }
    // PopulateDicts();
    return absl::OkStatus();
  }

  virtual absl::Status Attach() override final {
    int err = Skel::attach(skel_);
    if (err) {
      return absl::ErrnoToStatus(errno, "Failed to attach BPF object.");
    }
    return loader_->ObjectAttach(*this);
  }

  virtual absl::Status Detach() override final {
    auto ret = loader_->ObjectDetach(*this);
    if (!ret.ok()) {
      return ret;
    }
    Skel::detach(skel_);
    return absl::OkStatus();
  }

  virtual void Destroy() override final {
    loader_->ObjectDestroy(*this);
    Skel::destroy(skel_);
    skel_ = nullptr;
  }

  const Skel *operator->() const { return skel_; }

  Skel *operator->() { return skel_; }

  const Skel *Get() const { return skel_; }

  std::optional<Program> GetBPFProgram(std::string_view name) const {
    auto it = progs_.find(name);
    if (it == progs_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  std::optional<Map> GetBPFMap(std::string_view name) const {
    auto it = maps_.find(name);
    if (it == maps_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

 private:
  void PopulateDicts() {
    auto progp = reinterpret_cast<struct bpf_program **>(&skel_->progs);
    auto nr_progs = sizeof(skel_->progs) / sizeof(progp);
    std::span<struct bpf_program *> progs(progp, nr_progs);

    for (const auto p : progs) {
      auto name = bpf_program__name(p);
      progs_[name] = Program(p);
    }

    auto mapp = reinterpret_cast<struct bpf_map **>(&skel_->maps);
    auto nr_maps = sizeof(skel_->maps) / sizeof(mapp);
    std::span<struct bpf_map *> maps(mapp, nr_maps);

    for (const auto m : maps) {
      auto name = bpf_map__name(m);
      maps_[name] = Map(m);
    }
  }

  Skel *skel_;
  Loader *loader_;
};

}  // namespace bpf
}  // namespace ffkx

#endif
