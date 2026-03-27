{% skip_file if flag?(:without_interpreter) %}
require "./spec_helper"

describe Crystal::Repl::Interpreter do
  context "bugs" do
    it "doesn't pass self to top-level method" do
      interpret(<<-CRYSTAL).should eq(1)
        struct Int32
          def foo(x)
            self
          end
        end

        def value
          1
        end

        module Moo
          def self.moo
            1.foo(value)
          end
        end

        Moo.moo
      CRYSTAL
    end

    it "doesn't pass self to top-level method (FileNode)" do
      interpret(<<-CRYSTAL).should eq(1)
        enum Color
          Red
          Green
          Blue
        end

        class Object
          def should(expectation)
            self
          end
        end

        def eq(value)
          value
        end

        private def t(type : Color)
          type
        end

        other = 2
        e = Color::Green.should eq(t :green)
        e.value
      CRYSTAL
    end

    it "breaks from current block, not from outer block" do
      interpret(<<-CRYSTAL).should eq(2)
        def twice
          # index: 1, block_caller: 0

          yield
          yield
        end

        def bar
          # index: 4, block_caller: 3
          yield
        end

        def foo
          # index: 3, block_caller: 2
          bar do
            # index: 5, block_caller: 2
            yield
          end
        end

        # index: 0

        x = 0

        twice do
          # index: 2
          x += 1
          foo do
            # index: 6

            # parent frame has block_caller: 2,
            # that's where we have to go to
            break
          end
        end

        x
      CRYSTAL
    end

    it "doesn't incorrectly consider a non-closure as closure" do
      interpret(<<-CRYSTAL, prelude: "prelude").should eq("false")
        c = 0
        ->{
          c
          ->{}.closure?
        }.call
      CRYSTAL
    end

    it "doesn't override local variable value with block var with the same name" do
      interpret(<<-CRYSTAL).should eq(0)
        def block
          yield 1
        end

        def block2
          yield 10
        end

        def foo
          block do |i|
          end

          i = 0
          block2 do |x|
            i
          end
        end

        foo
      CRYSTAL
    end

    it "does leading zeros" do
      interpret(<<-CRYSTAL, prelude: "prelude").should eq("8")
        0_i8.leading_zeros_count
      CRYSTAL
    end

    it "does multidispatch on virtual struct" do
      interpret(<<-CRYSTAL).should be_true
        abstract struct Base
        end

        struct Foo < Base
          @x : Int32 | Char

          def initialize
            @x = 0
          end

          def foo
            @x.is_a?(Int32)
          end
        end

        struct Bar < Base
          def foo
            false
          end
        end

        address = Foo.new.as(Base)
        address.foo
      CRYSTAL
    end

    it "correctly puts virtual metaclass type in union" do
      interpret(<<-CRYSTAL).should eq("Bar")
        abstract struct Foo
        end

        struct Bar < Foo
        end

        struct Baz < Foo
        end

        class Class
          def name : String
            {{ @type.name.stringify }}
          end
        end

        foo = Bar.new.as(Foo)
        foo2 = foo || nil
        foo2.class.name
      CRYSTAL
    end

    it "does multidispatch on virtual struct union nil" do
      interpret(<<-CRYSTAL).should be_true
        abstract struct Foo
          @value = 1
        end

        struct Bar < Foo
        end

        struct Baz < Foo
        end

        class Object
          def itself
            a = 1
            self
          end
        end

        foo = Bar.new.as(Foo)
        bar = (foo || nil).itself
        bar.is_a?(Bar)
     CRYSTAL
    end

    it "handles self in inlined method with arguments (#16210)" do
      interpret(<<-CRYSTAL, prelude: "prelude").should eq(%("hello"))
        class Foo
          property x : String?

          def initialize(@x : String? = nil)
          end
        end

        foo = Foo.new("hello")
        foo.x.not_nil!("test")
      CRYSTAL
    end

    it "returns concrete type with typeof (#16377)" do
      interpret(<<-CRYSTAL, prelude: "prelude").should eq("true")
        class Foo
        end

        class Bar < Foo
        end

        foo = Bar.new.as(Foo)
        typeof(foo) == Foo
      CRYSTAL
    end

    it "upcasts argument when passing to union type parameter (#16484)" do
      interpret(<<-CRYSTAL, prelude: "prelude").should eq(%("[\\"1\\", \\"\\", \\"a\\"]"))
        module MetadataValueConverter
          def self.arg_to_log(arg) : String
            arg.to_s
          end

          def self.arg_to_log(arg : Enumerable) : String
            (arg.to_a.map { |a| arg_to_log(a) }).to_s
          end

          def self.arg_to_log(arg : Int) : String
            arg.to_i64.to_s
          end

          def self.arg_to_log(arg : Int32 | String) : String
            arg.to_s
          end
        end

        args = [1, nil, "a"]
        MetadataValueConverter.arg_to_log(args)

      CRYSTAL
    end

    it "looks up local vars in parent scopes after looking up local vars in current scope and closured scope (#15489)" do
      interpret(<<-CRYSTAL).should eq("parser")
        def capture(&block)
          block
        end

        def scoped(&)
          yield 1
        end

        scoped do |parser|
          capture do
            parser
          end
          parser # Error: BUG: missing downcast_distinct from String to Int32 (Crystal::NonGenericClassType to Crystal::IntegerType)
        end

        parser = "parser"
      CRYSTAL
    end

    it "doesn't error if def body is InstanceVar and virtual dispatch has only one subclass (#16278)" do
      interpret(<<-CRYSTAL).should eq(0)
        abstract class A
          abstract def foo : Int32

          def bar
            foo
          end
        end

        class B < A
          @test = 0

          def foo : Int32
            @test
          end
        end

        B.new.as(A).bar
      CRYSTAL
    end

    it "sets type of Expressions node in if branches (#16486)" do
      interpret(<<-CRYSTAL, prelude: "prelude").should eq(%("done"))
        class Model
          def self.foreign_key_for_association(sym : Symbol) : Symbol | Nil
            nil
          end

          def self.through_key_for_association(sym : Symbol) : Symbol | Nil
            nil
          end
        end

        class Query
          def self.where(key : Symbol, ids : Array) : Query
            new
          end

          def initialize
          end
        end

        def delete_dependents(queryable, destroy_assoc, ids, tx)
          through_key = queryable.through_key_for_association(destroy_assoc)
          if through_key.nil?
            foreign_key = queryable.foreign_key_for_association(destroy_assoc)
            return if foreign_key.nil?
            q = Query.where(foreign_key, ids)
          end
        end

        delete_dependents(Model, :test, [1, 2], nil)
        "done"
      CRYSTAL
    end

    it "downcasts from NilableType to ReferenceUnionType (#16596)" do
      interpret(<<-CRYSTAL).should be_true
        abstract class Base
        end

        class Gen(T) < Base
        end

        Gen(Int64).new

        if gen = Gen(Int32).new.as(Base).as?(Gen) # Error: BUG: missing downcast_distinct from (Gen(T) | Nil) to (Gen(Int32) | Gen(Int64)) (Crystal::NilableType to Crystal::ReferenceUnionType)
          gen.is_a?(Gen(Int32))
        else
          false
        end
      CRYSTAL
    end

    it "does a value cast from a union type including a module to that module" do
      interpret(<<-CRYSTAL).should eq(1)
        module M
          def foo; 1; end
        end

        struct S
          include M
        end

        v = S.new.as(Int32 | M)

        if v.is_a?(M)
          v.foo
        else
          0
        end
      CRYSTAL
    end

    it "executes inherited hook expansions in ClassDef" do
      interpret(<<-CRYSTAL).should eq(1)
        class Foo
          macro inherited
            def self.foo
              1
            end
          end
        end

        class Bar < Foo
        end

        Bar.foo
      CRYSTAL
    end

    it "executes included hook expansions in Include" do
      interpret(<<-CRYSTAL).should eq(1)
        module Moo
          macro included
            def self.foo
              1
            end
          end
        end

        class Bar
          include Moo
        end

        Bar.foo
      CRYSTAL
    end

    it "executes extended hook expansions in Extend" do
      interpret(<<-CRYSTAL).should eq(1)
        module Moo
          macro extended
            def self.foo
              1
            end
          end
        end

        class Bar
          extend Moo
        end

        Bar.foo
      CRYSTAL
    end

    it "executes method_added hook expansions in Def" do
      interpret(<<-CRYSTAL, prelude: "prelude").should eq(%("foo"))
        class Foo
          @@last_method : String?

          def self.last_method
            @@last_method
          end

          macro method_added(m)
            @@last_method = {{m.name.stringify}}
          end

          def foo
          end
        end

        Foo.last_method.not_nil!
      CRYSTAL
    end

    it "does a value cast from a union type including a module to that module (mixed class/struct)" do
      interpret(<<-CRYSTAL).should eq(2)
        module M
          def foo; 1; end
        end

        struct S
          include M
        end

        class C
          include M
        end

        v1 = S.new.as(Int32 | M)
        x = 0
        if v1.is_a?(M)
          x += v1.foo
        end

        v2 = C.new.as(Int32 | M)
        if v2.is_a?(M)
          x += v2.foo
        end

        x
      CRYSTAL
    end
    it "handles union size discrepancy when unboxing (index out of bounds bug)" do
      interpret(<<-CRYSTAL, prelude: "prelude").should eq("true")
        module Instance
        end

        struct Changeset(T)
          include Instance
          def initialize(@data : T)
            @changes = {} of Symbol => V
          end
          def get_field(field : Symbol) : V
            @changes[field]
          end
          def changes
            @changes
          end
        end

        alias V = String | Instance | Array(Instance) | Nil

        struct S1
          @name : String?
          def initialize(@name = nil)
          end
        end

        class C1
          include Instance
        end

        # We need to define eq and should to avoid pulling in the whole spec library
        # which might be too heavy for a unit test, but here we want to reproduce the exact issue.
        # Actually, the interpret helper in spec uses a minimal prelude.
        # Let's use a simpler version of the repro that doesn't depend on spec.

        def test(v : V, expected_type : Class)
          v.is_a?(Instance)
        end

        cs = Changeset(C1).new(C1.new)
        cs.changes[:a] = Changeset(C1).new(C1.new).as(Instance)
        v = cs.get_field(:a)
        # This call might trigger the upcast from V (24) to Subset (32) if the compiler filters it.
        # To be sure, we reproduce the situation where a subset is used.
        
        res = v.is_a?(Instance)
        res
      CRYSTAL
    end
  end
end
