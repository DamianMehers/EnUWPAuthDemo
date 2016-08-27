/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 */
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Thrift;
using Thrift.Collections;
using Thrift.Protocol;
using Thrift.Transport;
namespace Evernote.EDAM.Type
{

  #if !SILVERLIGHT && !NETFX_CORE
  [Serializable]
  #endif
  public partial class NotebookRestrictions : TBase
  {
    private bool _noReadNotes;
    private bool _noCreateNotes;
    private bool _noUpdateNotes;
    private bool _noExpungeNotes;
    private bool _noShareNotes;
    private bool _noEmailNotes;
    private bool _noSendMessageToRecipients;
    private bool _noUpdateNotebook;
    private bool _noExpungeNotebook;
    private bool _noSetDefaultNotebook;
    private bool _noSetNotebookStack;
    private bool _noPublishToPublic;
    private bool _noPublishToBusinessLibrary;
    private bool _noCreateTags;
    private bool _noUpdateTags;
    private bool _noExpungeTags;
    private bool _noSetParentTag;
    private bool _noCreateSharedNotebooks;
    private SharedNotebookInstanceRestrictions _updateWhichSharedNotebookRestrictions;
    private SharedNotebookInstanceRestrictions _expungeWhichSharedNotebookRestrictions;

    public bool NoReadNotes
    {
      get
      {
        return _noReadNotes;
      }
      set
      {
        __isset.noReadNotes = true;
        this._noReadNotes = value;
      }
    }

    public bool NoCreateNotes
    {
      get
      {
        return _noCreateNotes;
      }
      set
      {
        __isset.noCreateNotes = true;
        this._noCreateNotes = value;
      }
    }

    public bool NoUpdateNotes
    {
      get
      {
        return _noUpdateNotes;
      }
      set
      {
        __isset.noUpdateNotes = true;
        this._noUpdateNotes = value;
      }
    }

    public bool NoExpungeNotes
    {
      get
      {
        return _noExpungeNotes;
      }
      set
      {
        __isset.noExpungeNotes = true;
        this._noExpungeNotes = value;
      }
    }

    public bool NoShareNotes
    {
      get
      {
        return _noShareNotes;
      }
      set
      {
        __isset.noShareNotes = true;
        this._noShareNotes = value;
      }
    }

    public bool NoEmailNotes
    {
      get
      {
        return _noEmailNotes;
      }
      set
      {
        __isset.noEmailNotes = true;
        this._noEmailNotes = value;
      }
    }

    public bool NoSendMessageToRecipients
    {
      get
      {
        return _noSendMessageToRecipients;
      }
      set
      {
        __isset.noSendMessageToRecipients = true;
        this._noSendMessageToRecipients = value;
      }
    }

    public bool NoUpdateNotebook
    {
      get
      {
        return _noUpdateNotebook;
      }
      set
      {
        __isset.noUpdateNotebook = true;
        this._noUpdateNotebook = value;
      }
    }

    public bool NoExpungeNotebook
    {
      get
      {
        return _noExpungeNotebook;
      }
      set
      {
        __isset.noExpungeNotebook = true;
        this._noExpungeNotebook = value;
      }
    }

    public bool NoSetDefaultNotebook
    {
      get
      {
        return _noSetDefaultNotebook;
      }
      set
      {
        __isset.noSetDefaultNotebook = true;
        this._noSetDefaultNotebook = value;
      }
    }

    public bool NoSetNotebookStack
    {
      get
      {
        return _noSetNotebookStack;
      }
      set
      {
        __isset.noSetNotebookStack = true;
        this._noSetNotebookStack = value;
      }
    }

    public bool NoPublishToPublic
    {
      get
      {
        return _noPublishToPublic;
      }
      set
      {
        __isset.noPublishToPublic = true;
        this._noPublishToPublic = value;
      }
    }

    public bool NoPublishToBusinessLibrary
    {
      get
      {
        return _noPublishToBusinessLibrary;
      }
      set
      {
        __isset.noPublishToBusinessLibrary = true;
        this._noPublishToBusinessLibrary = value;
      }
    }

    public bool NoCreateTags
    {
      get
      {
        return _noCreateTags;
      }
      set
      {
        __isset.noCreateTags = true;
        this._noCreateTags = value;
      }
    }

    public bool NoUpdateTags
    {
      get
      {
        return _noUpdateTags;
      }
      set
      {
        __isset.noUpdateTags = true;
        this._noUpdateTags = value;
      }
    }

    public bool NoExpungeTags
    {
      get
      {
        return _noExpungeTags;
      }
      set
      {
        __isset.noExpungeTags = true;
        this._noExpungeTags = value;
      }
    }

    public bool NoSetParentTag
    {
      get
      {
        return _noSetParentTag;
      }
      set
      {
        __isset.noSetParentTag = true;
        this._noSetParentTag = value;
      }
    }

    public bool NoCreateSharedNotebooks
    {
      get
      {
        return _noCreateSharedNotebooks;
      }
      set
      {
        __isset.noCreateSharedNotebooks = true;
        this._noCreateSharedNotebooks = value;
      }
    }

    public SharedNotebookInstanceRestrictions UpdateWhichSharedNotebookRestrictions
    {
      get
      {
        return _updateWhichSharedNotebookRestrictions;
      }
      set
      {
        __isset.updateWhichSharedNotebookRestrictions = true;
        this._updateWhichSharedNotebookRestrictions = value;
      }
    }

    public SharedNotebookInstanceRestrictions ExpungeWhichSharedNotebookRestrictions
    {
      get
      {
        return _expungeWhichSharedNotebookRestrictions;
      }
      set
      {
        __isset.expungeWhichSharedNotebookRestrictions = true;
        this._expungeWhichSharedNotebookRestrictions = value;
      }
    }


    public Isset __isset;
    #if !SILVERLIGHT && !NETFX_CORE
    [Serializable]
    #endif
    public struct Isset {
      public bool noReadNotes;
      public bool noCreateNotes;
      public bool noUpdateNotes;
      public bool noExpungeNotes;
      public bool noShareNotes;
      public bool noEmailNotes;
      public bool noSendMessageToRecipients;
      public bool noUpdateNotebook;
      public bool noExpungeNotebook;
      public bool noSetDefaultNotebook;
      public bool noSetNotebookStack;
      public bool noPublishToPublic;
      public bool noPublishToBusinessLibrary;
      public bool noCreateTags;
      public bool noUpdateTags;
      public bool noExpungeTags;
      public bool noSetParentTag;
      public bool noCreateSharedNotebooks;
      public bool updateWhichSharedNotebookRestrictions;
      public bool expungeWhichSharedNotebookRestrictions;
    }

    public NotebookRestrictions() {
    }

    public void Read (TProtocol iprot)
    {
      TField field;
      iprot.ReadStructBegin();
      while (true)
      {
        field = iprot.ReadFieldBegin();
        if (field.Type == TType.Stop) { 
          break;
        }
        switch (field.ID)
        {
          case 1:
            if (field.Type == TType.Bool) {
              NoReadNotes = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 2:
            if (field.Type == TType.Bool) {
              NoCreateNotes = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 3:
            if (field.Type == TType.Bool) {
              NoUpdateNotes = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 4:
            if (field.Type == TType.Bool) {
              NoExpungeNotes = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 5:
            if (field.Type == TType.Bool) {
              NoShareNotes = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 6:
            if (field.Type == TType.Bool) {
              NoEmailNotes = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 7:
            if (field.Type == TType.Bool) {
              NoSendMessageToRecipients = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 8:
            if (field.Type == TType.Bool) {
              NoUpdateNotebook = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 9:
            if (field.Type == TType.Bool) {
              NoExpungeNotebook = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 10:
            if (field.Type == TType.Bool) {
              NoSetDefaultNotebook = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 11:
            if (field.Type == TType.Bool) {
              NoSetNotebookStack = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 12:
            if (field.Type == TType.Bool) {
              NoPublishToPublic = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 13:
            if (field.Type == TType.Bool) {
              NoPublishToBusinessLibrary = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 14:
            if (field.Type == TType.Bool) {
              NoCreateTags = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 15:
            if (field.Type == TType.Bool) {
              NoUpdateTags = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 16:
            if (field.Type == TType.Bool) {
              NoExpungeTags = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 17:
            if (field.Type == TType.Bool) {
              NoSetParentTag = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 18:
            if (field.Type == TType.Bool) {
              NoCreateSharedNotebooks = iprot.ReadBool();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 19:
            if (field.Type == TType.I32) {
              UpdateWhichSharedNotebookRestrictions = (SharedNotebookInstanceRestrictions)iprot.ReadI32();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          case 20:
            if (field.Type == TType.I32) {
              ExpungeWhichSharedNotebookRestrictions = (SharedNotebookInstanceRestrictions)iprot.ReadI32();
            } else { 
              TProtocolUtil.Skip(iprot, field.Type);
            }
            break;
          default: 
            TProtocolUtil.Skip(iprot, field.Type);
            break;
        }
        iprot.ReadFieldEnd();
      }
      iprot.ReadStructEnd();
    }

    public void Write(TProtocol oprot) {
      TStruct struc = new TStruct("NotebookRestrictions");
      oprot.WriteStructBegin(struc);
      TField field = new TField();
      if (__isset.noReadNotes) {
        field.Name = "noReadNotes";
        field.Type = TType.Bool;
        field.ID = 1;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoReadNotes);
        oprot.WriteFieldEnd();
      }
      if (__isset.noCreateNotes) {
        field.Name = "noCreateNotes";
        field.Type = TType.Bool;
        field.ID = 2;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoCreateNotes);
        oprot.WriteFieldEnd();
      }
      if (__isset.noUpdateNotes) {
        field.Name = "noUpdateNotes";
        field.Type = TType.Bool;
        field.ID = 3;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoUpdateNotes);
        oprot.WriteFieldEnd();
      }
      if (__isset.noExpungeNotes) {
        field.Name = "noExpungeNotes";
        field.Type = TType.Bool;
        field.ID = 4;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoExpungeNotes);
        oprot.WriteFieldEnd();
      }
      if (__isset.noShareNotes) {
        field.Name = "noShareNotes";
        field.Type = TType.Bool;
        field.ID = 5;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoShareNotes);
        oprot.WriteFieldEnd();
      }
      if (__isset.noEmailNotes) {
        field.Name = "noEmailNotes";
        field.Type = TType.Bool;
        field.ID = 6;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoEmailNotes);
        oprot.WriteFieldEnd();
      }
      if (__isset.noSendMessageToRecipients) {
        field.Name = "noSendMessageToRecipients";
        field.Type = TType.Bool;
        field.ID = 7;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoSendMessageToRecipients);
        oprot.WriteFieldEnd();
      }
      if (__isset.noUpdateNotebook) {
        field.Name = "noUpdateNotebook";
        field.Type = TType.Bool;
        field.ID = 8;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoUpdateNotebook);
        oprot.WriteFieldEnd();
      }
      if (__isset.noExpungeNotebook) {
        field.Name = "noExpungeNotebook";
        field.Type = TType.Bool;
        field.ID = 9;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoExpungeNotebook);
        oprot.WriteFieldEnd();
      }
      if (__isset.noSetDefaultNotebook) {
        field.Name = "noSetDefaultNotebook";
        field.Type = TType.Bool;
        field.ID = 10;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoSetDefaultNotebook);
        oprot.WriteFieldEnd();
      }
      if (__isset.noSetNotebookStack) {
        field.Name = "noSetNotebookStack";
        field.Type = TType.Bool;
        field.ID = 11;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoSetNotebookStack);
        oprot.WriteFieldEnd();
      }
      if (__isset.noPublishToPublic) {
        field.Name = "noPublishToPublic";
        field.Type = TType.Bool;
        field.ID = 12;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoPublishToPublic);
        oprot.WriteFieldEnd();
      }
      if (__isset.noPublishToBusinessLibrary) {
        field.Name = "noPublishToBusinessLibrary";
        field.Type = TType.Bool;
        field.ID = 13;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoPublishToBusinessLibrary);
        oprot.WriteFieldEnd();
      }
      if (__isset.noCreateTags) {
        field.Name = "noCreateTags";
        field.Type = TType.Bool;
        field.ID = 14;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoCreateTags);
        oprot.WriteFieldEnd();
      }
      if (__isset.noUpdateTags) {
        field.Name = "noUpdateTags";
        field.Type = TType.Bool;
        field.ID = 15;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoUpdateTags);
        oprot.WriteFieldEnd();
      }
      if (__isset.noExpungeTags) {
        field.Name = "noExpungeTags";
        field.Type = TType.Bool;
        field.ID = 16;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoExpungeTags);
        oprot.WriteFieldEnd();
      }
      if (__isset.noSetParentTag) {
        field.Name = "noSetParentTag";
        field.Type = TType.Bool;
        field.ID = 17;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoSetParentTag);
        oprot.WriteFieldEnd();
      }
      if (__isset.noCreateSharedNotebooks) {
        field.Name = "noCreateSharedNotebooks";
        field.Type = TType.Bool;
        field.ID = 18;
        oprot.WriteFieldBegin(field);
        oprot.WriteBool(NoCreateSharedNotebooks);
        oprot.WriteFieldEnd();
      }
      if (__isset.updateWhichSharedNotebookRestrictions) {
        field.Name = "updateWhichSharedNotebookRestrictions";
        field.Type = TType.I32;
        field.ID = 19;
        oprot.WriteFieldBegin(field);
        oprot.WriteI32((int)UpdateWhichSharedNotebookRestrictions);
        oprot.WriteFieldEnd();
      }
      if (__isset.expungeWhichSharedNotebookRestrictions) {
        field.Name = "expungeWhichSharedNotebookRestrictions";
        field.Type = TType.I32;
        field.ID = 20;
        oprot.WriteFieldBegin(field);
        oprot.WriteI32((int)ExpungeWhichSharedNotebookRestrictions);
        oprot.WriteFieldEnd();
      }
      oprot.WriteFieldStop();
      oprot.WriteStructEnd();
    }

    public override string ToString() {
      StringBuilder sb = new StringBuilder("NotebookRestrictions(");
      sb.Append("NoReadNotes: ");
      sb.Append(NoReadNotes);
      sb.Append(",NoCreateNotes: ");
      sb.Append(NoCreateNotes);
      sb.Append(",NoUpdateNotes: ");
      sb.Append(NoUpdateNotes);
      sb.Append(",NoExpungeNotes: ");
      sb.Append(NoExpungeNotes);
      sb.Append(",NoShareNotes: ");
      sb.Append(NoShareNotes);
      sb.Append(",NoEmailNotes: ");
      sb.Append(NoEmailNotes);
      sb.Append(",NoSendMessageToRecipients: ");
      sb.Append(NoSendMessageToRecipients);
      sb.Append(",NoUpdateNotebook: ");
      sb.Append(NoUpdateNotebook);
      sb.Append(",NoExpungeNotebook: ");
      sb.Append(NoExpungeNotebook);
      sb.Append(",NoSetDefaultNotebook: ");
      sb.Append(NoSetDefaultNotebook);
      sb.Append(",NoSetNotebookStack: ");
      sb.Append(NoSetNotebookStack);
      sb.Append(",NoPublishToPublic: ");
      sb.Append(NoPublishToPublic);
      sb.Append(",NoPublishToBusinessLibrary: ");
      sb.Append(NoPublishToBusinessLibrary);
      sb.Append(",NoCreateTags: ");
      sb.Append(NoCreateTags);
      sb.Append(",NoUpdateTags: ");
      sb.Append(NoUpdateTags);
      sb.Append(",NoExpungeTags: ");
      sb.Append(NoExpungeTags);
      sb.Append(",NoSetParentTag: ");
      sb.Append(NoSetParentTag);
      sb.Append(",NoCreateSharedNotebooks: ");
      sb.Append(NoCreateSharedNotebooks);
      sb.Append(",UpdateWhichSharedNotebookRestrictions: ");
      sb.Append(UpdateWhichSharedNotebookRestrictions);
      sb.Append(",ExpungeWhichSharedNotebookRestrictions: ");
      sb.Append(ExpungeWhichSharedNotebookRestrictions);
      sb.Append(")");
      return sb.ToString();
    }

  }

}
