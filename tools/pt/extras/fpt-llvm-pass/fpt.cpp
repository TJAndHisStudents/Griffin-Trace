/* vim: set ts=8 sts=2 et sw=2: */

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Constants.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;
#include <list>
#include <map>
#include <sstream>
#include <fstream>
#include <set>
using namespace std;

cl::opt<std::string> extTaintFile("taintFile", cl::desc("<External Taint input File.>"), cl::init("-"));



//#define DEBUG
enum {
    TAINT_NULL = 0,
    TAINT_VAR,
    TAINT_FLD,
    TAINT_ARG,
    TAINT_RET,
    TAINT_OTH,
};

typedef struct {
    string programPath;
    string program;
    string caller;
    string callee;
    int argNum;
    string t_type;
    string taintLabel;
    bool isReturn;
    bool isGlobal;
} extTaint;

//May need new struct for globals..


typedef struct {
    int ta_type;
    union {
        Value *ta_var;
        struct {
            Type *f_struct;
            unsigned f_num;
        } ta_fld;
        struct {
            Function *a_func;
            unsigned a_num;
        } ta_arg;
        Function *ta_ret;
    } ta_un;
} Taint;

typedef struct {
    const char *p_sym;
    Taint p_from;
    Taint p_to;
} Prop;

list<Taint> taint_set;
list<Prop> prop_set;
list<extTaint> extTaint_set;
map<string,list<Taint>> D;
vector<CallInst *> externalCalls;
list<pair<string, Function*> > externallyCalled;
vector<Type*> processTypes;
vector<BitCastInst*> fpTypeCastOps;
set<BitCastInst*> taintedfpTypeCastops;

//Stats vars:
int indCalls;
int targets_local;
int targets_ext;
int targets_all;
int extCalls;
int extCallsFP;
int extCallsTaint;
set< pair<string, string> > retFunc_Label;
int sharedGlobs;
set<Value*> taintedCast;

int fptoVoid = 0;
int fptostruct = 0;
int fptoint = 0;
int fptoAny = 0;

int Anytofp = 0;
int voidtofp = 0;
int anontofp = 0;
int inttofp = 0;
int structtofp = 0;
int tstructtofp = 0;
//int tAnytofp = 0;


int structtostruct = 0;
int tstructtostruct =0;
int structtotstruct =0;

int fptofp = 0;
int tfptofp = 0;
int fptotfp = 0;

int tAnytofp =0;
int tfptoAny = 0;




struct FPT: public ModulePass {
    static char ID;
    FPT() : ModulePass(ID) {}


    static string getProgramName(string progPath)
    {
        //string progPath = externalTaint.programPath;
        progPath.erase( std::remove_if( progPath.begin(), progPath.end(), ::isspace ), progPath.end() );
        //errs()<<" \n Line :-  ",line;
        char delimiter = '/';
        string acc = "";
        for(int i = 0; i < progPath.size(); i++)
        {
            if(progPath[i] == delimiter)
            {
                acc = "";
            }
            else
                acc += progPath[i];
        }
        string progName = acc;
        // errs()<<"\n Program Name "<<progName;

        return progName;
    }

    static void write_Stats(string tmp)
    {
        std::error_code errcode;
      //  std::string tmp = M.getName(); //M.getModuleIdentifier();

        replace(tmp.begin(), tmp.end(), '\\', '_');
        std::string Filename;
        if(tmp.find("musl") != std::string::npos)
        {
            string progName = getProgramName(extTaintFile);
            Filename = tmp +"_"+ progName+ ".stats";
        }
        else
            Filename = tmp + ".stats";

        //std::string Filename =  tmp + ".stats";
        raw_fd_ostream File(Filename.c_str(), errcode,sys::fs::F_None);
        raw_ostream *stream = &File;
        if (errcode.value() != 0) {
            errs() << "Error opening file externalCalls.extern";
            //exit();
        }

        (*stream) << "\n Total ext Calls: "<<extCalls; //
        (*stream) << "\n Ext call with FP: "<<extCallsFP; //
        (*stream) << "\n Ext calls tainted: "<<extCallsTaint; //
        (*stream) << "\n Total indirect calls: "<<indCalls; //
        (*stream) << "\n Total targets      :  "<<targets_all;
        (*stream) << "\n Total targets local:  "<<targets_local;
        (*stream) << "\n Total targets ext  :  "<<targets_ext;
        (*stream) << "\n Number of shared globals : "<<sharedGlobs; //
        (*stream) << "\n New returning labels added : "<<retFunc_Label.size();
        (*stream) <<"\n Labels sent back to calling module: ";
        for(set< pair<string, string> >::iterator retl = retFunc_Label.begin(); retl != retFunc_Label.end();++retl)
        {
            (*stream) <<"\n"<<(*retl).first<<" -- "<<(*retl).second;
        }



    }
    //Function to read the taint coming from different modules.. ext calls, or returning taint or global taint.
    static void ReadTaintInput(){
        //Read external calls taint..
        std::ifstream srcFile (extTaintFile.c_str(),std::ifstream::in);
        std::string line;
        if(!srcFile)
        {
            //errs() << " Could not open the external taint Input file \n";
        }
        else
        {
            while(srcFile >> line)
            {
                line.erase( std::remove_if( line.begin(), line.end(), ::isspace ), line.end() );
                //errs()<<" \n Line :-  ",line;
                char delimiter = ',';
                vector<string> str;
                string acc = "";
                for(int i = 0; i < line.size(); i++)
                {
                    if(line[i] == delimiter)
                    {
                        str.push_back(acc);
                        acc = "";
                    }
                    else
                        acc += line[i];
                }
                str.push_back(acc);

                //Read the tokens in sequence and add in appropriate stuct..
                extTaint externalTaint;
                externalTaint.programPath = str.at(0);
                externalTaint.caller = str.at(1);
                externalTaint.callee = str.at(2);
                externalTaint.argNum = atoi(str.at(3).c_str());
                externalTaint.t_type = str.at(4);
                //externalTaint.taintLabel = str.at(5);


                //Get the program name only...
                string progName = getProgramName(externalTaint.programPath);
                externalTaint.program = progName;
                if(strcmp(externalTaint.t_type.c_str(),"ret")==0)
                    externalTaint.taintLabel = str.at(5);
                else
                    externalTaint.taintLabel = str.at(5) + "___"+progName;
                extTaint_set.push_back(externalTaint);

                //str.push_back(acc);
            }
        }
    }


    //Function that adds the new taint sources based on the external taint input...
    static void AddExtTaint(Module &M)
    {
        //iterate through the module.. when a match for the ext param is found
        //call prepare taint on it.. with some modification to add appropriate label to app point.. write custom if needed..
        //after preparing taint.. it might need to be matched in D with a symbol string..! which is later used for final target computation..
        // use this to check the is taint on the targets using is tainted by.. (verrify how taint_set.clear in whopointstome is effecting the overall sources..)

        /*1.	if caller not present then look for function, if present, add the taints on formal arguments of the externally called function. (taint in library)
          2.	If caller present then look for call to (external) function and add updated taint on the arguments. (returning taint on arguments....!)
          3.	If caller present and is of type - return type, look for call to function and add updated taint label to the ret val of the call stmt.(returning taint on ret val)
          4.	If caller not present and is return type…  (Invalid option)
        */

        for (Module::iterator F = M.begin(), E = M.end(); F != E; F++) {
            string funcName = F->getName();
            //check if caller or calleee.. both cannot be in the same module anyways..what happens when func with same name.. e.g main.!
            //For now process ext call... process returning taint later..
            for(list<extTaint>::iterator extT = extTaint_set.begin(); extT != extTaint_set.end();++extT)
            {
                if((strcmp(extT->t_type.c_str(),"ext")==0) && funcName==extT->callee)
                {
                  //nt  errs()<<"\n ext match found...";
                    //Record for outputting returning taints..
                    pair<string,Function*> extCall;
                    extCall.first = extT->caller;
                    extCall.second = F;
                    externallyCalled.push_back(extCall);

                 //nt   errs()<<"\n Callee matched...: "<<funcName;
                    Taint t = prepareTaint(F,extT->argNum);
                //    printTaint(&t);
                    //Add the taint to propagation set where symbol is the updated label.. and goes to the taint.
                    Prop p;
                    p.p_to = t;
                    p.p_sym = extT->taintLabel.c_str();
                  //  errs()<<"\n Adding properrty for sym :"<<p.p_sym;
                    bool proadded = addPropIfNotExist(&p);
                 //   errs()<<"\n Property was added .. : "<<proadded;


                    //This then also needs to get added in D.. for further processing..



                }
                else if((strcmp(extT->t_type.c_str(),"ret")==0) && funcName==extT->caller)
                {

                    //Caller matched.. attach the returning taint on the call instruction
                    //iterate over instructions to find the call stmt to the callee...
                 //   errs()<<"\n Returning taint detected.. for caller :"<<funcName;
                    int retArgnum = extT->argNum;
                    for (inst_iterator I = inst_begin(F), J = inst_end(F); I != J; I++) {
                        if (CallInst *ci = dyn_cast<CallInst>(&*I)) {

                            ///Check if extrenal call with a pointer param, if so run the taint check for each taint on the param and write in the file.
                            //errs()<<"\nExternal call Check.....";
                            Function * calledFunc = ci->getCalledFunction();
                            if(calledFunc && calledFunc->isDeclaration())
                            {
                                if(calledFunc->getName()==extT->callee)
                                {
                                    //callins to the ext call found.. add the returning taint here..
                               //     errs()<<"\n found the ext call to map ret edges.."<<retArgnum;
                                //    ci->dump();
                                    if(retArgnum==-1)
                                    {
                                        //Add taint label to return value.
                                  //      errs()<<"\n IDentifying taint for return value..";

                                         Value* retValue = dyn_cast<Value>(ci);


                                         Taint t  = prepareTaint(calledFunc);
                                   //      errs()<<"\n prepare taint done..";
                                         printTaint(&t);
                                   //      errs()<<"\n print taint done..";
                                         //Add the taint to propagation set where symbol is the updated label.. and goes to the taint.
                                         Prop p;
                                         p.p_to = t;
                                         p.p_sym = extT->taintLabel.c_str();
                                 //        errs()<<"\n Adding properrty for sym :"<<p.p_sym;
                                  //       retValue->dump();
                                         bool proadded = addPropIfNotExist(&p);
                                   //      errs()<<"\n Property was added .. : "<<proadded;
                                    }
                                    else
                                    { //Add taint label to the argument.
                                     //   errs()<<"\n IDentifying taint for argument value..";
                                        int argNum = ci->getNumArgOperands();
                                        if(retArgnum<argNum)
                                        {
                                            Value* taintedArg = ci->getArgOperand(retArgnum);
                                    //        errs()<<"\n Tainted arg: ";
                                    //        taintedArg->dump();
                                            Taint t  = prepareTaint(calledFunc,retArgnum);
                                    //        errs()<<"\n prepare taint done..";
                                     //       printTaint(&t);
                                    //          errs()<<"\n print taint done..";
                                            //Add the taint to propagation set where symbol is the updated label.. and goes to the taint.
                                            Prop p;
                                            p.p_to = t;
                                            p.p_sym = extT->taintLabel.c_str();
                                     //       errs()<<"\n Adding properrty for sym :"<<p.p_sym;
                                      //      taintedArg->dump();
                                            bool proadded = addPropIfNotExist(&p);
                                      //      errs()<<"\n Property was added .. : "<<proadded;
                                        }

                                    }


                                }

                            }
                        }
                    } //end of inst iterator.
                    //------
                }
            }
        }

        //        //Add taint on global vars...
        //        for(list<extTaint>::iterator extT = extTaint_set.begin(); extT != extTaint_set.end();++extT)
        //        {
        //            if(strcmp(extT->t_type,"Glob_ext"))
        //            {
        //                //add taint..
        //            }
        //            if(strcmp(extT->t_type,"Glob_avail"))
        //            {
        //                //add taint..
        //            }

        //        }

    }

    static bool isFunctionPointerType(Type *t) {
        //errs()<<"\n Check if func pointer type.. func";
        if(!t)
            return false;
        // t->dump();
        if (!t->isPointerTy())
            return false; // not even a pointer
        Type * t2 =t->getPointerElementType();
        if(!t2)
            return false;
        if (!t->getPointerElementType()->isFunctionTy())
            return false; // not a function pointer
        return true;
    }


    static bool isFunctionPointer(Value *v) {
        if (!v)
            return false;
        return isFunctionPointerType(v->getType());
    }

    // get type after n'th index in getelementptr
    static Type *typeOfGetElementPtr(GetElementPtrInst *e, unsigned n) {
        assert(n < e->getNumOperands() && "over the last index in getelementptr?");
        Value *val = e->getOperand(0);
        Type *ty = val->getType();
        for (unsigned i = 1; i <= n; i++) {
            if (ty->isPointerTy())
                ty = ty->getPointerElementType();
            else if (ty->isArrayTy())
                ty = ty->getArrayElementType();
            else if (ty->isStructTy())
                ty = ty->getStructElementType(
                            cast<ConstantInt>(e->getOperand(i))->getZExtValue());
            else
                assert(false && "unknown type in GEP?");
        }
        return ty;
    }

    static bool isSameStruct(StructType *a, StructType *b) {
        if (a == b)
            return true;
        if (a->hasName() && b->hasName())
            return !a->getName().substr(7).rsplit('.').first.compare(
                        b->getName().substr(7).rsplit('.').first);
        if (a->getNumElements() != b->getNumElements())
            return false;
        for (unsigned i = 0; i < a->getNumElements(); i++) {
            Type *fa = a->getElementType(i);
            Type *fb = b->getElementType(i);
            if (fa->isStructTy() != fb->isStructTy())
                return false;
            if (fa->isPointerTy() != fb->isPointerTy())
                return false;
        }
        return true;
    }

    static bool isSameTaint(Taint *a, Taint *b) {
        if (a->ta_type != b->ta_type)
            return false;
        switch (a->ta_type) {
        case TAINT_VAR:
            return a->ta_un.ta_var == b->ta_un.ta_var;
        case TAINT_FLD:
            if (a->ta_un.ta_fld.f_num != b->ta_un.ta_fld.f_num)
                return false;
            return isSameStruct(cast<StructType>(a->ta_un.ta_fld.f_struct),
                                cast<StructType>(b->ta_un.ta_fld.f_struct));
        case TAINT_ARG:
            if (a->ta_un.ta_arg.a_num != b->ta_un.ta_arg.a_num)
                return false;
            if (a->ta_un.ta_arg.a_func == NULL ||
                    b->ta_un.ta_arg.a_func == NULL)
                return true;
            return a->ta_un.ta_arg.a_func == b->ta_un.ta_arg.a_func;
        case TAINT_RET:
            if (a->ta_un.ta_ret == NULL ||
                    b->ta_un.ta_ret == NULL)
                return true;
            return a->ta_un.ta_ret == b->ta_un.ta_ret;
        case TAINT_OTH:
            return true;
        }
        assert(false && "logic error");
    }

    static void printTaint(Taint *t) {
        switch (t->ta_type) {
        case TAINT_VAR:
            errs() << *t->ta_un.ta_var << "\n";
            return;
        case TAINT_FLD:
            errs() << *t->ta_un.ta_fld.f_struct << ":" << t->ta_un.ta_fld.f_num << "\n";
            return;
        case TAINT_ARG:
            errs() << (t->ta_un.ta_arg.a_func? t->ta_un.ta_arg.a_func->getName(): "null");
            errs() << "():[" << t->ta_un.ta_arg.a_num << "]\n";
            return;
        case TAINT_RET:
            errs() << (t->ta_un.ta_ret? t->ta_un.ta_ret->getName(): "null");
            errs() << "():[R]\n";
            return;
        case TAINT_OTH:
            errs() << "other\n";
            return;
        }
        assert(false && "what is the taint type?");
    }

    // check if t equals any Taint in taint_set
    static bool addTaintIfNotExist(Taint *t) {
        if (t->ta_type == TAINT_NULL)
            return false; // ignore invalid taint
        for (list<Taint>::iterator i = taint_set.begin(); i != taint_set.end(); i++) {
            if (isSameTaint(&*i, t))
                return false;
        }
        taint_set.push_back(*t);
        return true;
    }

    // prepare Taint for a pointer operand
    static Taint prepareTaint(Value *val) {
        Taint t;
        assert(val && "prepare taint for NULL?");
        if (ConstantExpr *expr = dyn_cast<ConstantExpr>(val))
            val = expr->getAsInstruction(); // convert to instruction before processing
        if (BitCastInst *bci = dyn_cast<BitCastInst>(val))
            return prepareTaint(bci->getOperand(0)); // bitcast, let's move on
        if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(val)) {
            for (int i = gep->getNumOperands() - 2; i > 0; i--) {
                Type *ty = typeOfGetElementPtr(gep, i);
                assert(ty->isArrayTy() || ty->isStructTy());
                if (ty->isStructTy()) { // structure field
                    t.ta_type = TAINT_FLD;
                    t.ta_un.ta_fld.f_struct = ty;
                    t.ta_un.ta_fld.f_num = cast<ConstantInt>
                            (gep->getOperand(i + 1))->getZExtValue();
                    return t;
                }
            }
            return prepareTaint(gep->getPointerOperand());
        } else if (isa<AllocaInst>(val) || isa<GlobalVariable>(val)) { // simple FP
            t.ta_type = TAINT_VAR;
            t.ta_un.ta_var = val;
        } else if (isa<LoadInst>(val)) { // pointer to function pointer
            errs() << "[A2] " << *val << "\n";
            t.ta_type = TAINT_OTH;
        } else if (CallInst *ci = dyn_cast<CallInst>(val)) {
            t = prepareTaint(ci->getCalledFunction());
        }
        else
        {
            errs() << "[ERROR] " << *val<< "\n";
            //assert(false && "what is the value to taint?");
            t.ta_type = TAINT_NULL;
        }
        return t;
    }

    // prepare Taint for a function argument
    static Taint prepareTaint(Function *func, unsigned argno) {
        Taint t;
        t.ta_type = TAINT_ARG;
        t.ta_un.ta_arg.a_func = func;
        t.ta_un.ta_arg.a_num = argno;
        return t;
    }

    // prepare Taint for a function return
    static Taint prepareTaint(Function *func) {
        Taint t;
        t.ta_type = TAINT_RET;
        t.ta_un.ta_ret = func;
        return t;
    }

#define taint(...) do { \
    Taint t = prepareTaint(__VA_ARGS__); \
    addTaintIfNotExist(&t); \
} while (0);

    // report if the given value is tainted by t or a constant
    // function pointer specified by FN
    static bool isTaintedBy(Value *val, Taint *t, const char *FN) {
        if (!isFunctionPointer(val))
            return false; // we only care about FPs
        if (isa<Constant>(val)) {
            if (ConstantExpr *expr = dyn_cast<ConstantExpr>(val))
                return isTaintedBy(expr->getOperand(0), t, FN);
            if (const char *fn = constantFunctionPointerName(val))
                if (strcmp(fn, FN) == 0) // compare constant FP name with FN
                    return true;
            return false;
        }
        if (SelectInst *si = dyn_cast<SelectInst>(val)) {
            return isTaintedBy(si->getTrueValue(), t, FN) ||
                    isTaintedBy(si->getFalseValue(), t, FN);
        }
        if (BitCastInst *bci = dyn_cast<BitCastInst>(val)) {
            return isTaintedBy(bci->getOperand(0), t, FN);
        }
        if (PHINode *phi = dyn_cast<PHINode>(val)) {
            for (unsigned i = 0; i < phi->getNumIncomingValues(); i++)
                if (isTaintedBy(phi->getIncomingValue(i), t, FN))
                    return true;
            return false;
        }
        if (!t) // value is not a constant function pointer
            return false;
        Taint test;
        if (LoadInst *load = dyn_cast<LoadInst>(val)) { // value from LOAD
            Value *op = load->getOperand(0);
            test = prepareTaint(op);
        } else if (Argument *arg = dyn_cast<Argument>(val)) { // value from argument
            test = prepareTaint(arg->getParent(), arg->getArgNo());
        } else if (CallInst *ci = dyn_cast<CallInst>(val)) { // value from function ret
            test = prepareTaint(ci->getCalledFunction());
        } else if (isa<IntToPtrInst>(val)) { // ...
            return false;
        } else {
            errs() << "[ERROR] " << *val << "\n";
            assert(false && "what is the value operand??");
        }
        return isSameTaint(&test, t);
    }

    // report if a value is tainted by any Taint object in the list OR
    // by the specified symbol
    static bool isTainted(Value *val, list<Taint> *set, const char *FN) {
        for (list<Taint>::iterator T = set->begin(); T != set->end(); T++)
            if (isTaintedBy(val, &*T, FN))
                return true;
        return isTaintedBy(val, NULL, FN);
    }

    static const char *constantFunctionPointerName(Value *val) {
        if (!isFunctionPointer(val))
            return NULL;
        if (Constant *c = dyn_cast<Constant>(val)) {
            if (ConstantExpr *e = dyn_cast<ConstantExpr>(c))
                return constantFunctionPointerName(e->getOperand(0));
            const char *n = c->getName().data();
            if (strlen(n) > 0)
                return n;
        }
        return NULL;
    }

    static bool addPropIfNotExist(Prop *p) {
        if (!p->p_sym && p->p_from.ta_type == TAINT_NULL)
            return false;
        if (p->p_to.ta_type == TAINT_NULL)
            return false;
        for (list<Prop>::iterator P = prop_set.begin(); P != prop_set.end(); P++) {
            Prop *q = &*P;
            if (p->p_sym) {
                if (!q->p_sym)
                    continue;
                if (strcmp(p->p_sym, q->p_sym) != 0)
                    continue;
            } else {
                if (q->p_sym)
                    continue;
                if (!isSameTaint(&p->p_from, &q->p_from))
                    continue;
            }
            if (isSameTaint(&p->p_to, &q->p_to))
                return false;
        }
        prop_set.push_back(*p);
        return true;
    }

    static void updatePropSet(Value *val, Taint *p_to) {
        if (!isFunctionPointer(val))
            return; // we only care about FPs
        if (isa<Constant>(val)) {
            if (ConstantExpr *expr = dyn_cast<ConstantExpr>(val)) {
                updatePropSet(expr->getOperand(0), p_to);
            } else if (const char *fn = constantFunctionPointerName(val)) {
                Prop p;
                p.p_to = *p_to;
                p.p_sym = fn;
                addPropIfNotExist(&p);
            }
        } else if (SelectInst *si = dyn_cast<SelectInst>(val)) {
            updatePropSet(si->getTrueValue(), p_to);
            updatePropSet(si->getFalseValue(), p_to);
        } else if (BitCastInst *bci = dyn_cast<BitCastInst>(val)) {
            updatePropSet(bci->getOperand(0), p_to);
        } else if (PHINode *phi = dyn_cast<PHINode>(val)) {
            for (unsigned i = 0; i < phi->getNumIncomingValues(); i++)
                updatePropSet(phi->getIncomingValue(i), p_to);
        } else {
            Taint p_from;
            if (LoadInst *load = dyn_cast<LoadInst>(val)) { // value from LOAD
                p_from = prepareTaint(load->getPointerOperand());
            } else if (Argument *arg = dyn_cast<Argument>(val)) { // value from argument
                p_from = prepareTaint(arg->getParent(), arg->getArgNo());
            } else if (CallInst *ci = dyn_cast<CallInst>(val)) { // value from function ret
                p_from = prepareTaint(ci->getCalledFunction());
            } else if (isa<IntToPtrInst>(val)) { // ...
                return;
            } else {
                errs() << "[ERROR] " << *val << "\n";
                assert(false && "what is the value operand??");
            }
            Prop p = {NULL, p_from, *p_to};
            addPropIfNotExist(&p);
        }
    }

    static void constantTravelAndProp(Constant *c, GlobalVariable *gv, StructType *f_s, unsigned f_n) {
        Type *ty = c->getType();
        while (ConstantExpr *e = dyn_cast<ConstantExpr>(c)) {
            if (!e->isCast())
                break;
            c = e->getOperand(0);
        }
        if (const char *fn = constantFunctionPointerName(c)) {
            Prop p = {fn};
            if (gv) {
                p.p_to = prepareTaint(gv);
            } else {
                p.p_to.ta_type = TAINT_FLD;
                p.p_to.ta_un.ta_fld.f_struct = f_s;
                p.p_to.ta_un.ta_fld.f_num = f_n;
            }
            addPropIfNotExist(&p);
        }
        if (!ty->isArrayTy() && !ty->isStructTy())
            return;
        for (unsigned i = 0; i < c->getNumOperands(); i++) {
            Constant *val = cast<Constant>(c->getOperand(i));
            if (ty->isArrayTy())
                constantTravelAndProp(val, gv, f_s, f_n);
            else
                constantTravelAndProp(val, NULL, cast<StructType>(ty), i);
        }
    }

    static void initPropSet(Module &M) {
        //prop_set.clear();
        // function pointer initialized at compile time
        for (Module::global_iterator G = M.global_begin(); G != M.global_end(); G++) {
            GlobalVariable *gv = &*G;
            if (!gv->hasDefinitiveInitializer())
                continue;
            constantTravelAndProp(gv->getInitializer(), gv, NULL, 0);
            // errs()<<"\n Constant TRavel Prop.... for :"<<*gv;
        }
        for (Module::iterator F = M.begin(); F != M.end(); F++) {
            for (inst_iterator I = inst_begin(F); I != inst_end(F); I++) {
                Taint p_to;
                if (StoreInst *si = dyn_cast<StoreInst>(&*I)) {
                    Value *val = si->getValueOperand();
                    if (!isFunctionPointer(val))
                        continue;
                    p_to = prepareTaint(si->getPointerOperand());
                    updatePropSet(si->getValueOperand(), &p_to);
                } else if (CallInst *ci = dyn_cast<CallInst>(&*I)) {
                    for (unsigned i = 0; i < ci->getNumArgOperands(); i++) {
                        Value *operand = ci->getArgOperand(i);
                        if (!isFunctionPointer(operand))
                            continue;
                        Function *f = ci->getCalledFunction();
                        if (!f) { // try our best here!
                            const char *fn = constantFunctionPointerName(ci->getCalledValue());
                            if (fn)
                                f = M.getFunction(fn);
                        }

                        if (f == NULL) {
                            if (DILocation *Loc = ci->getDebugLoc()) {
                                unsigned lineInt = Loc->getLine();
                                StringRef file = Loc->getFilename();
                                StringRef dir = Loc->getDirectory();

                                stringstream ss;
                                ss << lineInt;
                                string lineString = ss.str();
                                errs() << "Called function is null " << dir << ":" << file << ":" << lineString << "\n";
                            }
                        }

                        p_to = prepareTaint(f, i);
                        updatePropSet(operand, &p_to);
                    }
                    //Identify the call to a library funciton and collect it as possible sinks..to later check if taint reaches those calls.

                    // CallInst *CI = dyn_cast<CallInst>(&*Iit);
                    //CallSite cs(&*Iit);

                    Function * calledFunc = ci->getCalledFunction();
                    if(calledFunc && calledFunc->isDeclaration())
                    {
                        //    errs()<<"\nPROPAGATE: Call Site with called func and IS delaration.. !!";
                        //  CI->dump();
                        // HandleLibraryFunctions(CI,parentFunction);
                        externalCalls.push_back(ci);
                    }


                    //--end of identifying lib funcs

                } else if (ReturnInst *ri = dyn_cast<ReturnInst>(&*I)) {
                    Value *ret = ri->getReturnValue();
                    if (!isFunctionPointer(ret))
                        continue;
                    p_to = prepareTaint(&*F);
                    updatePropSet(ret, &p_to);
                }
            }
        }
#ifdef DEBUG
        errs()<<"\n\n---Prop Set size: "<<prop_set.size();
        for (list<Prop>::iterator P = prop_set.begin(); P != prop_set.end(); P++) {
            Prop *p = &*P;
            if (p->p_sym)
                errs() << p->p_sym << "\n";
            else
                printTaint(&p->p_from);
            printTaint(&p->p_to);
            errs() << "\n";
        }
#endif

        //        //Print the collected external calls
        //        for(vector<CallInst*>::iterator cit = externalCalls.begin(); cit != externalCalls.end();++cit)
        //        {
        //            errs()<<"\n External call";
        //            (*cit)->dump();
        //        }

    }

    static list<Taint> *whoPointsToMe(Module &M, const char *FN) {
        // initialize taint set
        taint_set.clear();
        // start tainting
        unsigned taint_size;
        do {
            taint_size = taint_set.size();
            for (list<Prop>::iterator P = prop_set.begin(); P != prop_set.end(); P++) {
                Prop *p = &*P;
                if (p->p_sym && strcmp(p->p_sym, FN) == 0) {
                    addTaintIfNotExist(&p->p_to);
                } else {
                    for (list<Taint>::iterator T = taint_set.begin(); T != taint_set.end(); T++) {
                        if (isSameTaint(&p->p_from, &*T)) {
                            addTaintIfNotExist(&p->p_to);
                            break;
                        }
                    }
                }
            }
        } while (taint_set.size() > taint_size);

        return &taint_set;
    }

    bool doCheckGEP(GetElementPtrInst *gep) {
        Value *val = gep->getOperand(0);
        while (true) {
            if (isFunctionPointerType(val->getType()))
                return false;
            // convert BitCast operation to Instruction
            Instruction *insn = dyn_cast<Instruction>(val);
            if (!insn)
                if (ConstantExpr *e = dyn_cast<ConstantExpr>(val))
                    insn = e->getAsInstruction();
            // convert Instruction to BitCastInstruction if necessary
            if (!insn)
                break;
            BitCastInst *bci = dyn_cast<BitCastInst>(insn);
            if (!bci)
                break;
            val = bci->getOperand(0);
        }
        return true;
    }

    bool doCheckFptrArith(ConstantExpr *expr) {
        if (!expr)
            return true;

        if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(expr->getAsInstruction()))
            return doCheckGEP(gep);

        for (int i = 0; i < expr->getNumOperands(); i++) {
            ConstantExpr *subexpr = dyn_cast<ConstantExpr>(expr->getOperand(i));
            if (!subexpr)
                continue;
            if (!doCheckFptrArith(subexpr))
                return false;
        }

        return true;
    }

    void checkFptrArith(Module &M) {
        for (Module::global_iterator G = M.global_begin(); G != M.global_end(); G++) {
            GlobalVariable *gv = &*G;
            if (!gv->hasDefinitiveInitializer())
                continue;
            ConstantExpr *expr = dyn_cast<ConstantExpr>(gv->getInitializer());
            if (expr && !doCheckFptrArith(expr)) {
                errs() << "[A1] " << *gv << "\n";
                assert(false && "A1 violation detected");
            }
        }

        for (Module::iterator F = M.begin(); F != M.end(); F++) {
            for (inst_iterator I = inst_begin(F); I != inst_end(F); I++) {
                Instruction *inst = &*I;
                if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(inst))
                    if (!doCheckGEP(gep))
                        errs() << "[A1] " << *inst << "\n";
                for (int i = 0; i < inst->getNumOperands(); i++) {
                    ConstantExpr *expr = dyn_cast<ConstantExpr>(inst->getOperand(i));
                    if (!expr)
                        continue;
                    if (!doCheckFptrArith(expr))
                        errs() << "[A1] " << *inst << "\n";
                }
            }
        }
    }

    static bool CheckForContainedFuncPointer(Type * elemType)
    {
        if(elemType->isFunctionTy())
        {
            return true;
        }
        else{
            if(elemType->isPointerTy())
            {
                Type * cType = elemType->getPointerElementType();
                return CheckForContainedFuncPointer(cType);
            }

            if (!elemType->isArrayTy() && !elemType->isStructTy())
                return false;
            for (unsigned i = 0; i < elemType->getNumContainedTypes(); i++) {
                Type* conType = elemType->getContainedType(i);
                if(conType)
                    if(std::find(processTypes.begin(), processTypes.end(), conType) != processTypes.end())
                    {
                        processTypes.push_back(conType);
                        CheckForContainedFuncPointer(conType);
                    }
            }
        }
        return false;
    }

    static void CheckvisibilityandPrint(raw_ostream *stream, GlobalVariable * gv, Type* globType)
    {
        if(gv->hasDefaultVisibility())
        {
            (*stream) <<"\n Function Pointer Global and visible:";
            gv->print(*stream);
            (*stream) << "\nType : ";
            globType->print(*stream);
            sharedGlobs +=1;
        }
        if(gv->hasExternalLinkage())
        {
            (*stream) <<"\n **Function Pointer Global and external linkage:";
            gv->print(*stream);
            (*stream) << "\nType : ";
            globType->print(*stream);
            sharedGlobs +=1;
        }


    }

    static void ComputeExtandAvailGlobs(Module &M)
    {
        //Open a file add this information..  possibly one global file to track info for all binaries.. (append mode)
        std::error_code errcode;
        std::string tmp = M.getName(); //M.getModuleIdentifier();

        replace(tmp.begin(), tmp.end(), '\\', '_');
        std::string Filename =  "ExternGlobals.txt";
        raw_fd_ostream File(Filename.c_str(), errcode,sys::fs::F_Append);
        raw_ostream *stream = &File;
        if (errcode.value() != 0) {
            errs() << "Error opening file ExternGlobals.txt";
            //exit();
        }

        (*stream) <<"\n --------------------------------------------------------\nGlobal info for: "<<tmp<<"\n";
        for (Module::global_iterator G = M.global_begin(); G != M.global_end(); G++) {
            GlobalVariable *gv = &*G;
            Type* globType = gv->getType();
            if(isFunctionPointerType(globType))
            {
                CheckvisibilityandPrint(stream, gv, globType);
            }
            else if(globType->isPointerTy())
            {
                Type * elemType = globType->getPointerElementType(); //->dump();
                if(isFunctionPointerType(elemType))
                {
                    CheckvisibilityandPrint(stream, gv, globType);

                }
                else if(elemType->isPointerTy())
                    if(elemType->getPointerElementType()->isFunctionTy())
                    {
                        CheckvisibilityandPrint(stream, gv, globType);
                    }

                processTypes.clear();
                if(CheckForContainedFuncPointer(elemType))
                {
                    CheckvisibilityandPrint(stream, gv, globType);

                }
            }
        }

    }

    static void init_stats()
    {
        indCalls = 0;
        targets_local = 0;
        targets_ext = 0;
        targets_all = 0;
        extCalls = 0;
        extCallsFP = 0;
        extCallsTaint = 0;
        //list< pair<string, string> > retFunc_Label;
        sharedGlobs = 0;

        fptoVoid = 0;
        fptostruct = 0;
        fptoint = 0;
        fptoAny = 0;

        Anytofp = 0;
        voidtofp = 0;
        anontofp = 0;
        inttofp = 0;
        structtofp = 0;

        structtostruct = 0;
        tstructtostruct =0;
        structtotstruct =0;

        fptofp = 0;
        tfptofp = 0;
        fptotfp = 0;

        tAnytofp =0;
        tfptoAny = 0;



    }

    static void printCastStats(raw_ostream *stream3)
    {
        (*stream3) << "\n@@@ Cast op count ***    : "<<fpTypeCastOps.size();
        (*stream3) << "\n@@@ tainted Cast ops @@@ : "<<taintedfpTypeCastops.size();

        (*stream3) << "\n@@@ Function pointer to Any    : "<<fptoAny;
        (*stream3) << "\n@@@ Function pointer to void   : "<<fptoVoid;
        (*stream3) << "\n@@@ Function pointer to struct : "<<fptostruct;
        (*stream3) << "\n@@@ Function pointer to Int    : "<<fptoint;
        (*stream3) << "\n@@@ Function pointer to fp    : "<<fptofp;
        (*stream3) << "\n@@@ Function pointer to fp taint : "<<tfptofp;

        (*stream3) << "\n@@@ Any to Function pointer    : "<<Anytofp;
        (*stream3) << "\n@@@ void to Function pointer    : "<<voidtofp;
        (*stream3) << "\n@@@ int to Function pointer     : "<<inttofp;
        (*stream3) << "\n@@@ Struct to fp               : "<<structtofp;
        (*stream3) << "\n@@@ struct to struct            : "<<structtostruct;
        (*stream3) << "\n@@@ struct to struct tainted  : "<<tstructtostruct;
    }


    bool runOnModule(Module &M) override {
        init_stats();
        ReadTaintInput();
        AddExtTaint(M);
        checkFptrArith(M);
        initPropSet(M);
        ComputeExtandAvailGlobs(M);
        // collect results for each address-taken function
        for (list<Prop>::iterator P = prop_set.begin(); P != prop_set.end(); P++) {
            Prop *p = &*P;
            if (!p->p_sym)
                continue;
            if (D.find(p->p_sym) != D.end())
                continue;
            list<Taint>* ts = whoPointsToMe(M, p->p_sym);
            assert(!ts->empty());
            D[p->p_sym] = *ts;
#ifdef DEBUG
            // print taints per function
            errs()<<"\n Symbol and Who points to me taint set, (taints per function)--size of D "<<D.size()<<" - "<<prop_set.size()<<"\n";
            if (!ts->empty()) {
                errs() << p->p_sym << "\n";
                errs() << "------\n";
                for (list<Taint>::iterator it = ts->begin(); it != ts->end(); it++) {
                    printTaint(&*it);
                }
                errs() << "\n";
            }
#endif
        }


        std::error_code errcode;
        std::string tmp = M.getName(); //M.getModuleIdentifier();

        replace(tmp.begin(), tmp.end(), '\\', '_');
        std::string Filename =  tmp + "_extCalls.extern";
        raw_fd_ostream File(Filename.c_str(), errcode,sys::fs::F_None);
        raw_ostream *stream = &File;
        if (errcode.value() != 0) {
            errs() << "Error opening file externalCalls.extern";
            //exit();
        }
        //Output to be used as input for other modules.
        std::string Filename2 =  tmp + "_taintout.txt";
        raw_fd_ostream File2(Filename2.c_str(), errcode,sys::fs::F_None);
        raw_ostream *stream2 = &File2;
        if (errcode.value() != 0) {
            errs() << "Error opening file taintOut";
            //exit();
        }

        //Output to be used as input for other modules.
        std::string Filename3 =   "TypeCastOPerations4.txt";
        raw_fd_ostream File3(Filename3.c_str(), errcode,sys::fs::F_Append);
        raw_ostream *stream3 = &File3;
        if (errcode.value() != 0) {
            errs() << "Error opening file taintOut";
            //exit();
        }


        // list targets for each indirect CALL
        for (Module::iterator F = M.begin(), E = M.end(); F != E; F++) {
            int seq = 0;
            for (inst_iterator I = inst_begin(F), J = inst_end(F); I != J; I++) {
                if (CallInst *ci = dyn_cast<CallInst>(&*I)) {

                    ///Check if extrenal call with a pointer param, if so run the taint check for each taint on the param and write in the file.
                    //errs()<<"\nExternal call Check.....";
                    Function * calledFunc = ci->getCalledFunction();
                    if(calledFunc && calledFunc->isDeclaration())
                    {
                        //    errs()<<"\nPROPAGATE: Call Site with called func and IS delaration.. !!";
                        //  CI->dump();
                        // HandleLibraryFunctions(CI,parentFunction);
                        // externalCalls.push_back(ci);

                        //update stats for number of external calls:
                        extCalls += 1;

                        int args = ci->getNumArgOperands();

                        if(args>0)
                        {
                            //                            (*stream) <<"\n---";
                            //                            ci->print(*stream);
                            int i =0;
                            for(Use* arg = ci->arg_operands().begin();arg!=ci->arg_operands().end();++arg)
                            {
                                Value * ArgVal = arg->get();
                                //Check if a function pointer.. get the taint and print..
                                if(isFunctionPointer(ArgVal))
                                {
                                    extCallsFP +=1;
                                    (*stream) <<"\n--------------\nFunction: ";
                                    if(ci->getCalledFunction())
                                        (*stream) << ci->getCalledFunction()->getName() <<"\nStatement:  ";
                                    ci->print(*stream);
                                    (*stream) <<"\nLabel:  ";
                                    // ArgVal->print(*stream);
                                    for (map<string,list<Taint>>::iterator mi = D.begin(), ni = D.end(); mi != ni; mi++)
                                        if (isTainted(ArgVal, &mi->second, mi->first.c_str()))
                                        {
                                            (*stream) << mi->first << "\n";
                                            (*stream2) <<tmp<<","<< F->getName()<<","<<ci->getCalledFunction()->getName()<<","<<i<<","<<"ext"<<","<<mi->first<<"\n";
                                            extCallsTaint += 1;
                                        }


                                }

                                //Check if pointer and has taint..
                                else if(ArgVal->getType()->isPointerTy())
                                {
                                    for (map<string,list<Taint>>::iterator mi = D.begin(), ni = D.end(); mi != ni; mi++)
                                        if (isTainted(ArgVal, &mi->second, mi->first.c_str()))
                                        {
                                            (*stream) <<"\n--------------\nFunction: ";
                                            if(ci->getCalledFunction())
                                                (*stream) << ci->getCalledFunction()->getName() <<"\nStatement:  ";
                                            ci->print(*stream);
                                            (*stream) <<"\nLabel:  ";
                                            //ci->print(*stream);
                                            //(*stream) <<"\n** Tainted pointer Arg: ";
                                            //ArgVal->print(*stream);
                                            (*stream) << mi->first << "\n";
                                            (*stream2) <<tmp<<","<< F->getName()<<","<<ci->getCalledFunction()->getName()<<","<<i<<","<<"ext"<<","<<mi->first<<"\n";
                                            extCallsTaint += 1;
                                        }
                                }

                                // (*stream) <<"\n";
                                //                                arg->get()->print(*stream);
                                i++;
                            }
                        }
                        ///ToDO: External calls with just the return type func pointer.. no or any input parameter.


                    }
                    ///End of detecting tainted external calls.


                    if (ci->getCalledFunction() || constantFunctionPointerName(ci->getCalledValue()))
                        continue; // not an indirect CALL
                    if (SelectInst *si = dyn_cast<SelectInst>(ci->getCalledValue()))
                        if (constantFunctionPointerName(si->getTrueValue()) &&
                                constantFunctionPointerName(si->getFalseValue()))
                            continue;
                    if (ci->isInlineAsm())
                        continue;

                // commenting to reduce ammount of output.. for typecast check only..
                    // Print out the function name and the call instruction in the bitcode
                    // Access the metadata and print out the corresponding line number for inst.
                    if (DILocation *Loc = ci->getDebugLoc()) {
                        unsigned lineInt = Loc->getLine();
                        StringRef file = Loc->getFilename();
                        StringRef dir = Loc->getDirectory();

                        stringstream ss;
                        ss << lineInt;
                        string lineString = ss.str();

                        //stringstream metaDataStream;
                        //metaDataStream << dir << ":" << file << ":" << lineString;
                        //string metaData = metaDataStream.str();

                        errs() << dir << ":" << file << ":" << lineString << "\n";
                    }

                    errs() << "[" << F->getName() << ":" << seq << "]" << *ci << "\n";
                    errs() << "========\n";
                    //update stats for number of indirect calls.:
                    indCalls += 1;
                    for (map<string,list<Taint>>::iterator mi = D.begin(), ni = D.end(); mi != ni; mi++)
                        if (isTainted(ci->getCalledValue(), &mi->second, mi->first.c_str()))
                        {
                            errs() << mi->first << "\n";
                            //Some post checks on the targets for generating some stats..:
                            //add if not violation or error .....
                           if(mi->first.find("[") == std::string::npos)
                           {
                               targets_all += 1;
                               //string checks for local and ext targets..
                               if(mi->first.find("___") == std::string::npos)
                                   targets_local += 1;
                               else
                               {
                                   string Loacalprogname = getProgramName(tmp);
                                   if(mi->first.find(Loacalprogname) == std::string::npos)
                                     targets_ext += 1;
                               }

                           }
                        }

                    errs() << "\n";
                    seq++;

                }

                if (BitCastInst *bc = dyn_cast<BitCastInst>(&*I))
                {
                    //get operands and check if func pointer type.
                    Type* destType = bc->getDestTy();
                    Type* srcType = bc->getSrcTy();
                    processTypes.clear();
                    bool srcfp = CheckForContainedFuncPointer(srcType);
                    bool destfp = CheckForContainedFuncPointer(destType);
                    bool tainted =false;
                    if(srcfp || destfp)
                    {
                        tainted = false;
                        //Print the illegal typecast operations in one file all the binaries
                        (*stream3) <<"\n\nIllegal type cast detected in function : "<<F->getName()<<"\n src Type  : ";
                        srcType->print(*stream3);
                        (*stream3) <<"\n Dest Type : ";
                        destType->print(*stream3);

                        int operandC = bc->getNumOperands();
                        for(int i =0;i<operandC;i++)
                        {
                            Value* opVal = bc->getOperand(i);
                            for (map<string,list<Taint>>::iterator mi = D.begin(), ni = D.end(); mi != ni; mi++)
                                if (isTainted(opVal, &mi->second, mi->first.c_str()))
                                {
                                    if(taintedCast.insert(opVal).second)
                                    {
                                        (*stream3) <<"\n==== Operand Tainted with label: "<< mi->first;
                                        opVal->print(*stream3);
                                    }
                                    taintedfpTypeCastops.insert(bc);
                                    tainted = true;
                                }
                        }

                            if(srcfp) {
                                fptoAny+=1;
                                if(tainted) tfptoAny += 1;

                                if(destType->isFunctionTy()) {fptofp +=1;if(tainted) tfptofp +=1; }
                                if(destType->isVoidTy()) fptoVoid +=1;
                                if(destType->isPointerTy())
                                {
                                    Type * elemType = destType->getPointerElementType();
                                    if(elemType->isVoidTy()) fptoVoid +=1;
                                    if(elemType->isIntegerTy()) fptoint +=1;
                                    if(elemType->isFunctionTy())
                                    {   fptofp +=1;
                                        if(tainted) tfptofp +=1;
                                    }
                                    if(elemType->isStructTy())
                                    {
                                        fptostruct +=1;
                                        if(srcType->isStructTy()) {structtostruct +=1; if(tainted) tstructtostruct+=1;}
                                        if(srcType->isPointerTy())
                                        {
                                            Type * elemType2 = srcType->getPointerElementType();
                                            if(elemType2->isStructTy()) {structtostruct +=1; if(tainted) tstructtostruct+=1;}
                                        }

                                    }
                                }
                            }
                            else
                            {

                                if(destfp) {
                                    Anytofp +=1;
                                    if(tainted) tAnytofp +=1;
                                    if(srcType->isPointerTy())
                                    {
                                        Type * elemType = srcType->getPointerElementType();
                                        if(elemType->isVoidTy()) voidtofp +=1;
                                        if(elemType->isIntegerTy()) inttofp +=1;
                                        //                                    if(elemType->isFunctionTy())
                                        //                                    {   fptofp +=1;
                                        //                                        if(tainted) tfptofp +=1;
                                        //                                    }
                                        if(elemType->isStructTy())
                                        {
                                            structtofp +=1;
                                            if(tainted) tstructtofp +=1;
                                            //printCastStats(stream3);
                                            if(destType->isStructTy()) {structtostruct +=1; if(tainted) tstructtostruct+=1;}
                                            if(destType->isPointerTy())
                                            {
                                                Type * elemType2 = destType->getPointerElementType();
                                                if(elemType2->isStructTy()) {structtostruct +=1; if(tainted) tstructtostruct+=1;}
                                            }

                                        }

                                    }
                                }

                            }


                        fpTypeCastOps.push_back(bc);
                    }

                }
            }
            //Check if this function was externally called, if so output the taint on ref params and return type.
            // errs()<<"\n ExtCalled func size..:"<<externallyCalled.size();
            for(list<pair<string, Function*> >::iterator extFp = externallyCalled.begin();extFp != externallyCalled.end();++extFp)
            {
                if((extFp->second) == F)
                {
               //     errs()<<"\nFound externally called Function...: "<<F->getName();
                    //for all params of fucn/ptr type, perform is tainted by any symbol check..
                    // for return type of func/ptr type.. do is tainted by check..
                    for (map<string,list<Taint>>::iterator mi = D.begin(), ni = D.end(); mi != ni; mi++)
                    {
                        Function::arg_iterator argptr;
                        Function::arg_iterator e;
                        unsigned i;
                        for (i = 0, argptr = F->arg_begin(), e = F->arg_end(); argptr != e; ++i, ++argptr) {

                            // OpNode* argPHI = new OpNode(Instruction::PHI);
                            Value *argValue = argptr;

                            if (isTainted(argValue, &mi->second, mi->first.c_str()))
                            {
                           //     errs()<<"\nArgument ---- :"<<i;
                            //    argValue->dump();
                            //    errs() << mi->first << "\n";
                                //Output the appropriate updated taints on the parameters.. if the ___ not present, then add this as originating program..
                                string tLabel = mi->first;
                                if(tLabel.find("___") == std::string::npos)
                                {
                                    string progPath = M.getModuleIdentifier();
                                    string progName = getProgramName(progPath);
                                    tLabel = mi->first+"___"+progName;

                                  //  errs()<<"\n Updated Labels with current program.. :"<<tLabel;
                                    (*stream2) <<tmp<<","<<extFp->first<<","<<F->getName()<<","<<i<<","<<"ret"<<","<<tLabel<<"\n";
                                    // errs()<<tmp<<","<<extFp->first<<","<<F->getName()<<","<<i<<","<<"ret"<<","<<tLabel<<"\n";
                                    pair<string,string> retLabVal = {F->getName(),tLabel};
                                    retFunc_Label.insert(retLabVal);

                                }
                                else
                                    (*stream2) <<tmp<<","<<extFp->first<<","<<F->getName()<<","<<i<<","<<"ret"<<","<<tLabel<<"\n";
                                //tLabel
                                //Todos...: change the program path.. to reflect callers prog.., dont add repetitive labels
                            }
                        }
                        //Check return.. no direct func, iterate to get ret stmt..do only if rettype relevant..
                        //Value *retVal = F->ge
                        for (inst_iterator I = inst_begin(F), J = inst_end(F); I != J; I++) {
                            if (ReturnInst *ri = dyn_cast<ReturnInst>(&*I)) {
                                Value * retVal = ri->getReturnValue();
                                if (isTainted(retVal, &mi->second, mi->first.c_str()))
                                {
                           //         errs()<<"\n Return Value ---- :"<<i;
                            //        retVal->dump();
                             //       errs() << mi->first << "\n";
                                    string tLabel = mi->first;
                                    if(tLabel.find("___") == std::string::npos)
                                    {
                                        string progPath = M.getModuleIdentifier();
                                        string progName = getProgramName(progPath);
                                        tLabel = mi->first+"___"+progName;

                                   //     errs()<<"\n Updated Labels with current program.. :"<<tLabel;
                                        (*stream2) <<tmp<<","<<extFp->first<<","<<F->getName()<<","<<"-1"<<","<<"ret"<<","<<tLabel<<"\n";
                                        // errs()<<tmp<<","<<extFp->first<<","<<F->getName()<<","<<i<<","<<"ret"<<","<<tLabel<<"\n";
                                        pair<string,string> retLabVal = {F->getName(),tLabel};
                                        retFunc_Label.insert(retLabVal);

                                    }
                                    else
                                        (*stream2) <<tmp<<","<<extFp->first<<","<<F->getName()<<","<<"-1"<<","<<"ret"<<","<<tLabel<<"\n";
                                    //(*stream2) <<tmp<<","<<extFp->first<<","<<F->getName()<<","<<"-1"<<","<<"ret"<<","<<mi->first<<"\n";
                                }
                            }
                        } //end inst iter for ret..
                    }

                }
            } //end for ext called iterator.

        }

        if(fpTypeCastOps.size()>0)
        {
            (*stream3) << "\n@@@ Cast op count ***    : "<<fpTypeCastOps.size();
            (*stream3) << "\n@@@ tainted Cast ops @@@ : "<<taintedfpTypeCastops.size();

            (*stream3) << "\n@@@ Function pointer to Any    : "<<fptoAny;
            (*stream3) << "\n@@@ Function pointer to void   : "<<fptoVoid;
            (*stream3) << "\n@@@ Function pointer to struct : "<<fptostruct;
            (*stream3) << "\n@@@ Function pointer to Int    : "<<fptoint;
            (*stream3) << "\n@@@ Function pointer to fp    : "<<fptofp;
            (*stream3) << "\n@@@ Function pointer to fp taint : "<<tfptofp;

            (*stream3) << "\n@@@ Any to Function pointer    : "<<Anytofp;
            (*stream3) << "\n@@@ void to Function pointer    : "<<voidtofp;
            (*stream3) << "\n@@@ int to Function pointer     : "<<inttofp;
            (*stream3) << "\n@@@ Struct to fp               : "<<structtofp;
            (*stream3) << "\n@@@ struct to struct            : "<<structtostruct;
            (*stream3) << "\n@@@ tainted-struct to fp  : "<<tstructtofp;
            (*stream3) << "\n@@@ tainted- Any to fp  : "<<tAnytofp;
            (*stream3) << "\n@@@ tainted - fp to any  : "<<tfptoAny;
            (*stream3) << "\n@@@ struct to struct tainted  : "<<tstructtostruct;

            //errs() << "\n*** Cast op count ***    : "<<fpTypeCastOps.size();
            //errs() << "\n@@@ tainted Cast ops @@@ : "<<taintedfpTypeCastops.size();
            (*stream3) <<"\n --------------------------------------------------------\n@@@Type Cast Information for: "<<tmp<<"\n";
        }
        write_Stats(tmp);

        return false;
    }
};

char FPT::ID = 0;
static RegisterPass<FPT> fpt("fpt", "Function Pointer Targets");

struct ATF: public ModulePass {
    static char ID;
    ATF() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        FPT::initPropSet(M);
        for (list<Prop>::iterator P = prop_set.begin(); P != prop_set.end(); P++)
            if (P->p_sym)
                errs() << P->p_sym << "\n";
        return false;
    }
};

char ATF::ID = 0;
static RegisterPass<ATF> atf("atf", "Address-Taken Functions");

