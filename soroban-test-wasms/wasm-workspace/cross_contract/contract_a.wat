(module
  (type (;0;) (func (param i64 i64) (result i64)))
  (type (;1;) (func))
  (func (;0;) (type 0) (param i64 i64) (result i64)
    (local i32 i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 3
    global.set 0
    block  ;; label = @1
      local.get 0
      i64.const 255
      i64.and
      i64.const 4
      i64.ne
      local.get 1
      i64.const 255
      i64.and
      i64.const 4
      i64.ne
      i32.or
      br_if 0 (;@1;)
      local.get 0
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      local.tee 2
      local.get 1
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.add
      local.tee 4
      local.get 2
      i32.lt_u
      br_if 0 (;@1;)
      local.get 3
      local.get 4
      i32.store offset=8
      global.get 0
      i32.const 16
      i32.sub
      local.tee 2
      global.set 0
      local.get 2
      local.get 3
      i32.const 8
      i32.add
      i64.load32_u
      i64.const 32
      i64.shl
      i64.const 4
      i64.or
      i64.store offset=8
      local.get 2
      i64.const 0
      i64.store
      local.get 2
      i64.load offset=8
      local.get 2
      i32.const 16
      i32.add
      global.set 0
      local.get 3
      i32.const 16
      i32.add
      global.set 0
      return
    end
    unreachable)
  (func (;1;) (type 1)
    nop)
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "add" (func 0))
  (export "_" (func 1))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))
